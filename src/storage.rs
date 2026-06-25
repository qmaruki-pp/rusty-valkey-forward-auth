use crate::config::RVFAConfig;
use anyhow::Result;
use fred::prelude::*;
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Clone)]
pub(crate) struct TokenInfo {
    pub id: String,
    pub description: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ApiToken {
    pub sub: String,
    pub created_at: String,
    pub description: String,
}

pub(crate) async fn client_from_config(config: &RVFAConfig) -> Result<fred::clients::Client> {
    let mut valkey_config = Config::from_url(&config.valkey_url)?;
    if let Some(username) = &config.valkey_username {
        valkey_config.username = Some(username.clone());
    }
    if let Some(password) = &config.valkey_password {
        valkey_config.password = Some(password.clone());
    }
    valkey_config.database = Some(config.valkey_database_id);
    let client = Builder::from_config(valkey_config)
        .with_connection_config(|connection_config| {
            connection_config.connection_timeout = Duration::from_secs(5);
            connection_config.tcp = TcpConfig {
                nodelay: Some(true),
                ..Default::default()
            };
        })
        .build()?;

    Ok(client)
}

pub(crate) async fn create_api_token(
    client: &fred::clients::Client,
    user_sub: &str,
    token_hash: &str,
    description: &str,
) -> Result<()> {
    let created_at = OffsetDateTime::now_utc().format(&Rfc3339)?;

    let transaction = client.multi();
    let _: () = transaction
        .hset::<(), _, _>(
            format!("auth:token:{}", token_hash),
            [
                ("sub", user_sub),
                ("created_at", created_at.as_str()),
                ("description", description),
            ],
        )
        .await?;
    let _: () = transaction
        .sadd(format!("auth:user_tokens:{}", user_sub), vec![token_hash])
        .await?;

    let _: () = transaction.exec(true).await?;

    Ok(())
}

pub(crate) async fn list_user_tokens(
    client: &fred::clients::Client,
    user_sub: &str,
) -> Result<Vec<TokenInfo>> {
    // Get all token hashes for this user
    let token_hashes: Vec<String> = client
        .smembers(format!("auth:user_tokens:{}", user_sub))
        .await?;

    let mut tokens = Vec::new();

    // Fetch details for each token
    for token_hash in token_hashes {
        let values: Vec<Option<String>> = client
            .hmget(
                format!("auth:token:{}", token_hash),
                vec!["description", "created_at"],
            )
            .await?;

        if let [Some(description), Some(created_at)] = &values[..] {
            tokens.push(TokenInfo {
                id: token_hash,
                description: description.clone(),
                created_at: created_at.clone(),
            });
        }
    }

    Ok(tokens)
}

pub(crate) async fn read_api_token(
    client: &fred::clients::Client,
    token_hash: &str,
) -> Result<Option<ApiToken>> {
    let values: Vec<Option<String>> = client
        .hmget(
            format!("auth:token:{}", token_hash),
            vec!["sub", "created_at", "description"],
        )
        .await?;

    match &values[..] {
        [Some(sub), Some(created_at), Some(description)] => Ok(Some(ApiToken {
            sub: sub.clone(),
            created_at: created_at.clone(),
            description: description.clone(),
        })),
        _ => Ok(None),
    }
}

pub(crate) async fn read_api_token_sub(
    client: &fred::clients::Client,
    token_hash: &str,
) -> Result<Option<String>> {
    let sub: Option<String> = client
        .hget(format!("auth:token:{}", token_hash), "sub")
        .await?;

    Ok(sub)
}

pub(crate) async fn delete_api_token(
    client: &fred::clients::Client,
    token_hash: &str,
) -> Result<bool> {
    let script = r#"
        local token_hash = ARGV[1]
        local token_key = "auth:token:" .. token_hash
        local sub = redis.call('HGET', token_key, 'sub')

        if not sub then
            return 0
        end

        local user_tokens_key = "auth:user_tokens:" .. sub
        redis.call('DEL', token_key)
        redis.call('SREM', user_tokens_key, token_hash)

        return 1
    "#;

    let result: i64 = client
        .eval(script, Vec::<String>::new(), vec![token_hash])
        .await?;

    Ok(result == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::time::SystemTime;

    /// Helper function to create a test client connected to localhost:6379
    async fn setup_test_client() -> fred::clients::Client {
        let config = Config::from_url("valkey://localhost:6379").expect("Invalid Valkey URL");
        let client = Builder::from_config(config)
            .build()
            .expect("Failed to build client");
        client.connect();
        client
            .wait_for_connect()
            .await
            .expect("Failed to connect to Valkey");
        client
    }

    /// Helper function to generate unique test data using timestamp and thread ID
    fn test_suffix() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let thread_id = std::thread::current().id();

        format!("{}_{}_{:?}", nanos, counter, thread_id)
    }

    /// Helper function to cleanup test data
    async fn cleanup_keys(client: &fred::clients::Client, keys: Vec<String>) {
        for key in keys {
            let _: Result<(), _> = client.del(key).await;
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_create_api_token() {
        let client = setup_test_client().await;
        let suffix = test_suffix();
        let user_sub = format!("user_{}", suffix);
        let token_hash = format!("hash_{}", suffix);
        let description = "Test token";

        // Create the token
        create_api_token(&client, &user_sub, &token_hash, description)
            .await
            .expect("Failed to create token");

        // Verify the token hash exists
        let token_key = format!("auth:token:{}", token_hash);
        let exists: bool = client
            .exists(&token_key)
            .await
            .expect("Failed to check existence");
        assert!(exists, "Token hash should exist in Valkey");

        // Verify all fields are stored correctly
        let sub: Option<String> = client
            .hget(&token_key, "sub")
            .await
            .expect("Failed to get sub");
        assert_eq!(sub, Some(user_sub.clone()), "Sub should match");

        let stored_description: Option<String> = client
            .hget(&token_key, "description")
            .await
            .expect("Failed to get description");
        assert_eq!(
            stored_description,
            Some(description.to_string()),
            "Description should match"
        );

        let created_at: Option<String> = client
            .hget(&token_key, "created_at")
            .await
            .expect("Failed to get created_at");
        assert!(created_at.is_some(), "Created_at should exist");

        // Verify the hash is added to the user's token set
        let user_tokens_key = format!("auth:user_tokens:{}", user_sub);
        let is_member: bool = client
            .sismember(&user_tokens_key, &token_hash)
            .await
            .expect("Failed to check set membership");
        assert!(is_member, "Token hash should be in user's token set");

        // Cleanup
        cleanup_keys(&client, vec![token_key, user_tokens_key]).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_read_api_token() {
        let client = setup_test_client().await;
        let suffix = test_suffix();
        let user_sub = format!("user_{}", suffix);
        let token_hash = format!("hash_{}", suffix);
        let description = "Test read token";

        // Create a token first
        create_api_token(&client, &user_sub, &token_hash, description)
            .await
            .expect("Failed to create token");

        // Read it back
        let token = read_api_token(&client, &token_hash)
            .await
            .expect("Failed to read token");

        assert!(token.is_some(), "Token should exist");
        let token = token.unwrap();
        assert_eq!(token.sub, user_sub, "Sub should match");
        assert_eq!(token.description, description, "Description should match");
        assert!(
            !token.created_at.is_empty(),
            "Created_at should not be empty"
        );

        // Test reading a non-existent token
        let non_existent = read_api_token(&client, "nonexistent_hash")
            .await
            .expect("Failed to read non-existent token");
        assert!(
            non_existent.is_none(),
            "Non-existent token should return None"
        );

        // Cleanup
        cleanup_keys(
            &client,
            vec![
                format!("auth:token:{}", token_hash),
                format!("auth:user_tokens:{}", user_sub),
            ],
        )
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_read_api_token_sub() {
        let client = setup_test_client().await;
        let suffix = test_suffix();
        let user_sub = format!("user_{}", suffix);
        let token_hash = format!("hash_{}", suffix);
        let description = "Test sub read";

        // Create a token first
        create_api_token(&client, &user_sub, &token_hash, description)
            .await
            .expect("Failed to create token");

        // Read only the sub field
        let sub = read_api_token_sub(&client, &token_hash)
            .await
            .expect("Failed to read token sub");

        assert!(sub.is_some(), "Sub should exist");
        assert_eq!(sub.unwrap(), user_sub, "Sub should match");

        // Test reading a non-existent token
        let non_existent = read_api_token_sub(&client, "nonexistent_hash")
            .await
            .expect("Failed to read non-existent token sub");
        assert!(
            non_existent.is_none(),
            "Non-existent token should return None"
        );

        // Cleanup
        cleanup_keys(
            &client,
            vec![
                format!("auth:token:{}", token_hash),
                format!("auth:user_tokens:{}", user_sub),
            ],
        )
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_list_user_tokens() {
        let client = setup_test_client().await;
        let suffix = test_suffix();
        let user_sub = format!("user_{}", suffix);
        let token_hash1 = format!("hash1_{}", suffix);
        let token_hash2 = format!("hash2_{}", suffix);
        let token_hash3 = format!("hash3_{}", suffix);

        // Create multiple tokens for the same user
        create_api_token(&client, &user_sub, &token_hash1, "First token")
            .await
            .expect("Failed to create token 1");
        create_api_token(&client, &user_sub, &token_hash2, "Second token")
            .await
            .expect("Failed to create token 2");
        create_api_token(&client, &user_sub, &token_hash3, "Third token")
            .await
            .expect("Failed to create token 3");

        // List all tokens for the user
        let tokens = list_user_tokens(&client, &user_sub)
            .await
            .expect("Failed to list tokens");

        // Verify count matches expected
        assert_eq!(tokens.len(), 3, "Should have 3 tokens");

        // Verify all TokenInfo structs have correct data
        let hashes: Vec<&str> = tokens.iter().map(|t| t.id.as_str()).collect();
        assert!(
            hashes.contains(&token_hash1.as_str()),
            "Should contain token 1"
        );
        assert!(
            hashes.contains(&token_hash2.as_str()),
            "Should contain token 2"
        );
        assert!(
            hashes.contains(&token_hash3.as_str()),
            "Should contain token 3"
        );

        for token in &tokens {
            assert!(
                !token.description.is_empty(),
                "Description should not be empty"
            );
            assert!(
                !token.created_at.is_empty(),
                "Created_at should not be empty"
            );
        }

        // Test listing for a user with no tokens
        let empty_tokens = list_user_tokens(&client, "nonexistent_user")
            .await
            .expect("Failed to list tokens for non-existent user");
        assert_eq!(
            empty_tokens.len(),
            0,
            "Should return empty Vec for user with no tokens"
        );

        // Cleanup
        cleanup_keys(
            &client,
            vec![
                format!("auth:token:{}", token_hash1),
                format!("auth:token:{}", token_hash2),
                format!("auth:token:{}", token_hash3),
                format!("auth:user_tokens:{}", user_sub),
            ],
        )
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_api_token() {
        let client = setup_test_client().await;
        let suffix = test_suffix();
        let user_sub = format!("user_{}", suffix);
        let token_hash = format!("hash_{}", suffix);
        let description = "Test delete token";

        // Create a token
        create_api_token(&client, &user_sub, &token_hash, description)
            .await
            .expect("Failed to create token");

        // Delete it
        let deleted = delete_api_token(&client, &token_hash)
            .await
            .expect("Failed to delete token");
        assert!(deleted, "Delete should return true");

        // Verify the token hash is removed from Valkey
        let token_key = format!("auth:token:{}", token_hash);
        let exists: bool = client
            .exists(&token_key)
            .await
            .expect("Failed to check existence");
        assert!(!exists, "Token hash should be removed from Valkey");

        // Verify the hash is removed from the user's token set
        let user_tokens_key = format!("auth:user_tokens:{}", user_sub);
        let is_member: bool = client
            .sismember(&user_tokens_key, &token_hash)
            .await
            .expect("Failed to check set membership");
        assert!(
            !is_member,
            "Token hash should be removed from user's token set"
        );

        // Test deleting a non-existent token
        let not_deleted = delete_api_token(&client, "nonexistent_hash")
            .await
            .expect("Failed to delete non-existent token");
        assert!(
            !not_deleted,
            "Delete should return false for non-existent token"
        );

        // Cleanup
        cleanup_keys(&client, vec![user_tokens_key]).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_full_crud_lifecycle() {
        let client = setup_test_client().await;
        let suffix = test_suffix();
        let user_sub = format!("user_{}", suffix);
        let token_hash = format!("hash_{}", suffix);
        let description = "Lifecycle test token";

        // Create a token
        create_api_token(&client, &user_sub, &token_hash, description)
            .await
            .expect("Failed to create token");

        // Read it back (both full and sub-only)
        let full_token = read_api_token(&client, &token_hash)
            .await
            .expect("Failed to read token");
        assert!(full_token.is_some(), "Token should exist after creation");
        assert_eq!(
            full_token.as_ref().unwrap().sub,
            user_sub,
            "Sub should match"
        );

        let sub_only = read_api_token_sub(&client, &token_hash)
            .await
            .expect("Failed to read token sub");
        assert_eq!(sub_only, Some(user_sub.clone()), "Sub should match");

        // List user tokens (verify it's there)
        let tokens = list_user_tokens(&client, &user_sub)
            .await
            .expect("Failed to list tokens");
        assert_eq!(tokens.len(), 1, "Should have 1 token");
        assert_eq!(tokens[0].id, token_hash, "Hash should match");
        assert_eq!(
            tokens[0].description, description,
            "Description should match"
        );

        // Delete it
        let deleted = delete_api_token(&client, &token_hash)
            .await
            .expect("Failed to delete token");
        assert!(deleted, "Delete should return true");

        // Verify it's gone (read should return None, list should be empty)
        let token_after_delete = read_api_token(&client, &token_hash)
            .await
            .expect("Failed to read token after delete");
        assert!(
            token_after_delete.is_none(),
            "Token should not exist after deletion"
        );

        let tokens_after_delete = list_user_tokens(&client, &user_sub)
            .await
            .expect("Failed to list tokens after delete");
        assert_eq!(
            tokens_after_delete.len(),
            0,
            "Should have 0 tokens after deletion"
        );

        // Cleanup (just in case)
        cleanup_keys(
            &client,
            vec![
                format!("auth:token:{}", token_hash),
                format!("auth:user_tokens:{}", user_sub),
            ],
        )
        .await;
    }
}
