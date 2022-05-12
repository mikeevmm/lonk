use argh::FromArgs;
use core::panic;
use validators::traits::ValidateString;
use warp::{http::Response, hyper::StatusCode, Filter};

#[macro_use]
/// Module containing custom defined macros.
mod macros {
    /// Macros useful for debug contexts.
    ///
    /// For example, `ifdbg!(expr)` replaces the $expr with () when the compile
    /// profile is set to `RELEASE`.
    #[macro_use]
    pub mod debug {
        #[cfg(debug_assertions)]
        /// debuginfo!("debug info", "release info") is functionally equivalent
        /// to
        ///
        /// ```
        /// if DEBUG {
        ///     "debug info"
        /// } else {
        ///     "release info"
        /// }
        /// ```
        ///
        /// An overloaded `debuginfo!(str)` is defined to mean
        /// `debuginfo!(str, "Internal error.")`.
        macro_rules! debuginfo {
            ($log:literal) => {
                $log
            };
            ($log:literal,$alt:literal) => {
                $log
            };
        }

        #[cfg(not(debug_assertions))]
        macro_rules! debuginfo {
            ($log:literal) => {
                "Internal error."
            };
            ($log:literal,$alt:literal) => {
                $alt
            };
        }

        #[cfg(debug_assertions)]
        /// `ifdbg!($expr)` is functionally equivalent to
        ///
        /// ```
        /// if DEBUG {
        ///     $expr
        /// } else {
        ///     ()
        /// }
        /// ```
        ///
        /// It can be particularly useful in combination with `eprintln!()`,
        /// i.e.,
        ///
        /// ```
        /// ifdbg!(eprintln!("Debug error information."))
        /// ```
        macro_rules! ifdbg {
            ($expr:expr) => {
                $expr;
            };
        }

        #[cfg(not(debug_assertions))]
        macro_rules! ifdbg {
            ($expr:expr) => {
                ()
            };
        }
    }
}

/// Affine to static configuration.
mod conf {
    use serde::{Deserialize, Serialize};
    use std::{net::IpAddr, path::PathBuf, str::FromStr};
    use validators::prelude::*;
    use warp::{filters::BoxedFilter, Filter};

    #[derive(Deserialize, Serialize, Debug, Clone)]
    /// Configuration settings specific to the (Redis) database.
    /// See the `Default` implementation for sensible values.
    pub struct DbConfig {
        /// The URL of the Redis database.
        pub address: String,
        /// The expiration time of entries, in seconds.
        pub expire_seconds: usize,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    /// Rules for constructing (shortened URL) slugs.
    pub struct SlugRules {
        /// (Exact) length of the slugs.
        pub length: usize,
        /// Valid characters to include in the slug.
        pub chars: String,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    /// Configuration settings for what happens for `GET /`, specifically
    /// whether and which file or directory to serve.
    pub enum ServeDirRules {
        /// Serve the specified file.
        File(PathBuf),
        /// Serve the specified directory
        /// (enumerated if `index.html` is not present).
        Dir(PathBuf),
    }

    #[derive(Serialize, Deserialize, Debug, Validator, Clone)]
    #[validator(ip(local(Allow), port(Must)))]
    /// Struct specifying where the HTTP server should be served.
    ///
    /// This struct is meant to be parsed from a larger configuration struct.
    pub struct ServeAddr {
        /// Serve the HTTP server at this IP
        pub ip: IpAddr,
        /// Serve the HTTP server at this port
        pub port: u16,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    /// Configuration for the service of the HTTP server.
    ///
    /// See the definitions of [`ServeDirRules`] and [`ServeAddr`] for more
    /// information on the specific configuration.
    pub struct ServeRules {
        /// Configuration for the contents served.
        pub dir: ServeDirRules,
        /// Configuration for the serve location.
        pub addr: ServeAddr,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    /// Configuration struct. This struct is a typed representation of the
    /// configuration file, with each of the domain-specific configurations
    /// defined as their own type (in reflection of a JSON structure, for
    /// example). See the definition of each of the member structs for more
    /// information.
    pub struct Config {
        /// Configuration regarding the Redis database.
        pub db: DbConfig,
        /// Configuration regarding the types of (URL shorten) slugs produced.
        pub slug_rules: SlugRules,
        /// Configuration regarding where and how the HTTP server is served.
        pub serve_rules: ServeRules,
    }

    // Default implementations

    impl Default for DbConfig {
        fn default() -> Self {
            Self {
                address: "redis://127.0.0.1:6379".to_string(),
                expire_seconds: 259200, // 3 days
            }
        }
    }

    impl Default for SlugRules {
        fn default() -> Self {
            Self {
                length: 5,
                chars: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                    .to_string(),
            }
        }
    }

    impl ServeDirRules {
        pub fn to_filter(&self) -> BoxedFilter<(warp::fs::File,)> {
            match self {
                ServeDirRules::File(file) => warp::fs::file(file.clone()).boxed(),
                ServeDirRules::Dir(dir) => warp::fs::dir(dir.clone()).boxed(),
            }
        }
    }

    impl Default for ServeDirRules {
        fn default() -> Self {
            ServeDirRules::Dir(PathBuf::from_str("/etc/lonk/served").unwrap())
        }
    }

    impl Default for ServeAddr {
        fn default() -> Self {
            Self {
                ip: [127, 0, 0, 1].into(),
                port: 8080,
            }
        }
    }

    impl Default for ServeRules {
        fn default() -> Self {
            Self {
                dir: Default::default(),
                addr: ServeAddr::default(),
            }
        }
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                db: Default::default(),
                slug_rules: Default::default(),
                serve_rules: Default::default(),
            }
        }
    }
}

/// Affine to live service.
mod service {
    use validators::prelude::*;

    #[derive(Validator)]
    #[validator(http_url(local(NotAllow)))]
    #[derive(Clone, Debug)]
    #[allow(dead_code)]
    /// A struct representing a URL.
    pub struct HttpUrl {
        url: validators::url::Url,
        is_https: bool,
    }

    #[derive(Validator)]
    #[validator(domain(ipv4(Allow), local(NotAllow), at_least_two_labels(Must), port(Allow)))]
    #[allow(dead_code)]
    pub struct Domain {
        domain: String,
        port: Option<u16>,
    }

    impl std::fmt::Display for HttpUrl {
        fn fmt(&self, f: &mut validators_prelude::Formatter<'_>) -> std::fmt::Result {
            self.url.fmt(f)
        }
    }

    impl HttpUrl {
        /// Transform this into an `Err(())` if the url is not a `Domain`.
        pub fn strict(self) -> Result<Self, ()> {
            match self.url.domain() {
                None => return Err(()),
                Some(domain) => {
                    if Domain::parse_string(domain).is_err() {
                        return Err(());
                    }
                }
            }
            Ok(self)
        }
    }

    /// Database management, including messaging and work stealing.
    pub mod db {
        use super::{slug::Slug, HttpUrl};
        use async_object_pool::Pool;
        use redis::Commands;
        use std::sync::Arc;
        use tokio::sync;
        use validators::prelude::*;

        #[derive(Debug)]
        /// Struct representing a connection to the Redis database, for
        /// management of Slug <-> URL registry.
        ///
        /// Behind the curtains, `SlugDatabase` implements an asynchronous
        /// scheme, based on message passing and a continuously running `Tokio`
        /// worker. This results in `SlugDatabase` being a thin wrapper around
        /// a single `mpsc::UnboundedSender` channel. Because this is the
        /// single producer, when `SlugDatabase` is dropped, every related
        /// `Tokio` worker is shut down as well.
        ///
        /// See the documentation of [`SlugDbMessage`] for more information on
        /// the specific messages to be exchanged with the `SlugDatabase`.
        pub struct SlugDatabase {
            tx: sync::mpsc::UnboundedSender<SlugDbMessage>,
        }

        #[derive(Clone, Debug)]
        /// Response for a request to add a URL to the database.
        pub enum AddResult {
            /// The URL was successfully added, and assigned this slug.
            Success(Slug),
            /// The URL could not be added to the database.
            Fail,
        }

        #[derive(Clone, Debug)]
        /// Response for a request to translate a slug to a URL.
        pub enum GetResult {
            /// The corresponding URL was found, and has this value.
            Found(HttpUrl),
            /// The given slug does not exist in the database.
            NotFound,
            /// There was some internal error when trying to translate the slug.
            InternalError,
        }

        /// Request to the slug database for a particular action.
        ///
        /// Since the [`SlugDatabase`] operates asynchronously and on a
        /// message-passing basis (see the documentation of [`SlugDatabase`] for
        /// more information), actions are performed by sending such a message,
        /// and then (asynchronously) listening on the provided `oneshot`
        /// channel for a response from the database.
        ///
        /// For example, when inserting a slug:
        ///
        /// ```
        /// let requested_slug = "my_Slug";
        /// let url = "https://example.com";
        /// let (tx, rx) = sync::oneshot::channel();
        /// self.tx
        ///     .send(SlugDbMessage::Add(requested_slug, url, tx))
        ///     .expect("The SlugDbMessage channel is unexpectedly closed.");
        /// let db_response = rx.await;
        /// ```
        enum SlugDbMessage {
            /// Insert a Slug -> URL registry into the database.
            Insert(Slug, HttpUrl, sync::oneshot::Sender<AddResult>),
            /// Get the URL associated to a slug (if it exists).
            Get(Slug, sync::oneshot::Sender<GetResult>),
        }

        impl core::fmt::Debug for SlugDbMessage {
            fn fmt(&self, f: &mut validators_prelude::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Insert(arg0, arg1, _) => f
                        .debug_tuple("Add")
                        .field(arg0)
                        .field(arg1)
                        .field(&"oneshot::Sender<AddResult>")
                        .finish(),
                    SlugDbMessage::Get(arg0, _) => f
                        .debug_tuple("Get")
                        .field(arg0)
                        .field(&"oneshot::Sender<Url>")
                        .finish(),
                }
            }
        }

        impl SlugDatabase {
            /// Create a new slug database form a Redis `Client` object.
            /// This is the preferred way to create a new `SlugDatabase`.
            ///
            /// Currently, every entry in the database is expected/set to
            /// expire. This may be subject to change in the future.
            ///
            /// Example:
            ///
            /// ```
            /// let redis_client = redis::Client::open("redis://127.0.0.1:6379")
            ///                        .expect("Error opening Redis database.");
            /// let expiration = 1000; // Entries expire after 1000 seconds.
            /// SlugDatabase::from_client(redis_client, expiration)
            /// ```
            pub fn from_client(client: redis::Client, expire_seconds: usize) -> Self {
                let (tx, rx) = sync::mpsc::unbounded_channel::<SlugDbMessage>();
                tokio::spawn(SlugDatabase::db_dispatch_worker(client, rx, expire_seconds));
                SlugDatabase { tx }
            }

            /// Tokio thread responsible for receiving requests of connection to
            /// the SlugDatabase and dispatching them to working threads.
            async fn db_dispatch_worker(
                client: redis::Client,
                mut rx: sync::mpsc::UnboundedReceiver<SlugDbMessage>,
                expire_seconds: usize,
            ) {
                // redis::Connection pool.
                // Per the documentation of the redis crate, these are not
                // pooled internally.
                let pool = Arc::new(sync::Mutex::new(Pool::new(100)));

                // Receive and dispatch the incoming messages.
                while let Some(msg) = { rx.recv().await } {
                    // Get a connection from the pool
                    // (or make a new one if needed)
                    let mut connection = {
                        (*pool.lock().await)
                            .take_or_create(|| {
                                client
                                    .get_connection()
                                    .expect("Could not open connection to Redis server.")
                            })
                            .await
                    };

                    let pool = pool.clone();
                    tokio::spawn(async move {
                        // Dispatch the message
                        match msg {
                            SlugDbMessage::Insert(requested_slug, url, response_channel) => {
                                SlugDatabase::dispatch_insert(
                                    &mut connection,
                                    requested_slug,
                                    url,
                                    response_channel,
                                    expire_seconds,
                                )
                                .await
                            }
                            SlugDbMessage::Get(slug, response_channel) => {
                                SlugDatabase::dispatch_get(&mut connection, slug, response_channel)
                                    .await
                            }
                        }

                        // Put the redis connection item back into the pool
                        (*pool.lock().await).put(connection).await;
                    });
                }
            }

            /// Dispatch a request to the database to insert a Slug -> URL
            /// registry.
            ///
            /// This function is not expected to be called directly, but rather
            /// by the `db_dispatch_worker` function, as a result of a
            /// `SlugDbMessage::Insert` message.
            async fn dispatch_insert(
                connection: &mut redis::Connection,
                requested_slug: Slug,
                url: HttpUrl,
                response_channel: sync::oneshot::Sender<AddResult>,
                expire_seconds: usize,
            ) {
                let url_str = url.to_string();
                let url_key = format!("url:{}", url_str);

                // Check that the URL is not already present in the DB
                // This is, to some extent, a protection against collision attacks.
                match connection.get::<String, Option<String>>(url_key.clone()) {
                    Ok(Some(slug)) => {
                        let slug_key = format!("slug:{}", slug);

                        // The URL was already present.
                        // Refresh the expiration.
                        // (If this operation fails it cannot be corrected for.)
                        connection
                            .expire::<String, ()>(url_key, expire_seconds)
                            .ok();
                        connection
                            .expire::<String, ()>(slug_key, expire_seconds)
                            .ok();

                        // Return the original slug.
                        response_channel
                            .send(AddResult::Success(Slug::unchecked_from_str(slug)))
                            .ok();
                        return;
                    }
                    Err(err) => {
                        response_channel.send(AddResult::Fail).ok();
                        ifdbg!(eprintln!("{}", err));
                        return;
                    }
                    Ok(None) => {} // continue with insertion
                };

                // The URL is not present in the database; insert it.

                let slug_key = format!("slug:{}", requested_slug.inner_str());

                // Make sure that there's no collision with the slug; if so, we
                // are in one of two situations: either we got really unlucky,
                // or the slug space has been exhausted.
                // In any case, to be safe, fail the operation.
                match connection.get::<String, Option<String>>(slug_key.clone()) {
                    Ok(Some(_)) => {
                        // Collision!
                        response_channel.send(AddResult::Fail).ok();
                        eprintln!(
                            "Collision for slug {}! 
                            Slug space may have been exhausted.
                            If you see this message repeatedly,
                            consider increasing the slug size.",
                            slug_key
                        );
                        return;
                    }
                    Err(err) => {
                        // Internal error in communication.
                        response_channel.send(AddResult::Fail).ok();
                        ifdbg!(eprintln!("{}", err));
                        return;
                    }
                    Ok(None) => {} // continue with insertion
                };

                let add_result = connection.set_ex::<String, String, ()>(
                    slug_key,
                    url_str.clone(),
                    expire_seconds,
                );

                if add_result.is_ok() {
                    connection
                        .set_ex::<String, String, ()>(
                            url_key,
                            requested_slug.inner_str().to_string(),
                            expire_seconds,
                        )
                        .ok(); // If this failed we have no way of correcting for it.
                }

                response_channel
                    .send(match add_result {
                        Ok(_) => AddResult::Success(requested_slug),
                        Err(err) => {
                            ifdbg!(eprintln!("{}", err));
                            AddResult::Fail
                        }
                    })
                    .ok(); // If the receiver has hung up there's nothing we can do.
            }

            /// Dispatch a request to get from the database the URL associated
            /// to a given slug (if it exists).
            ///
            /// This function is not expected to be called directly, but rather
            /// by the `db_dispatch_worker` function, as a result of a
            /// `SlugDbMessage::Get` message.
            async fn dispatch_get(
                connection: &mut redis::Connection,
                slug: Slug,
                response_channel: sync::oneshot::Sender<GetResult>,
            ) {
                let result: Result<Option<String>, _> =
                    connection.get(format!("slug:{}", slug.inner_str()));
                match result {
                    Ok(Some(url)) => response_channel.send(GetResult::Found(
                        HttpUrl::parse_string(url).expect("Mismatched URL in the database."),
                    )),
                    Ok(None) => response_channel.send(GetResult::NotFound),
                    Err(err) => {
                        ifdbg!(eprintln!("{}", err));
                        response_channel.send(GetResult::InternalError)
                    }
                }
                .ok(); // If the receiver has hung up there's nothing we can do.
            }

            /// Request a slug <-> URL registry to be inserted into the
            /// database.
            ///
            /// This is an asynchronous operation; as such, a
            /// `oneshot::Receiver` is returned, rather than a result. One
            /// should await on this receiver for the result of the operation.
            /// (Note that, as a consequence of this, this function is *not*
            /// asynchronous.)
            ///
            /// Note that the `requested_slug` argument is just that: a request.
            /// If the response is a `Success`, it will include the actual new
            /// slug. In particular, if the URL was already present in the
            /// database, the already associated slug will be returned.
            ///
            /// Example:
            ///
            /// ```
            /// match db.insert_slug("mY_Slug", url).await {
            ///     Success(slug) => {},// `slug` now points to the URL.
            ///     Fail => panic!()    // There was some problem, and the
            ///                         // registry was not inserted.
            /// }
            /// ```
            pub fn insert_slug(
                &self,
                requested_slug: Slug,
                url: HttpUrl,
            ) -> sync::oneshot::Receiver<AddResult> {
                let (tx, rx) = sync::oneshot::channel();
                self.tx
                    .send(SlugDbMessage::Insert(requested_slug, url, tx))
                    .expect("The SlugDbMessage channel is unexpectedly closed.");
                rx
            }

            /// Request the URL associated to the provided slug, if it exists.
            ///
            /// This is an asynchronous operation; as such, a
            /// `oneshot::Receiver` is returned, rather than a result. One
            /// should await on this receiver for the result of the operation.
            /// (Note that, as a consequence of this, this function is *not*
            /// asynchronous.)
            pub fn get_slug(&self, slug: Slug) -> sync::oneshot::Receiver<GetResult> {
                let (tx, rx) = sync::oneshot::channel();
                self.tx
                    .send(SlugDbMessage::Get(slug, tx))
                    .expect("The SlugDbMessage channel is unexpectedly closed.");
                rx
            }
        }
    }

    /// Affine to slug definition, generation, parsing, etc.
    pub mod slug {
        use crate::conf::SlugRules;
        use rand::prelude::*;
        use std::collections::BTreeSet;

        /// A struct responsible for constructing random slugs, or validating
        /// existing ones.
        pub struct SlugFactory {
            slug_length: usize,
            slug_chars: BTreeSet<char>,
            slug_chars_indexable: Vec<char>,
        }

        #[derive(Clone, Debug)]
        /// A slug, as in the sequence of characters in the URL shortener that
        /// aliases to a given URL.
        ///
        /// Usually this is a/the argument in the `GET` request to the link
        /// shortener.
        ///
        /// `Slug`s are typically produced by [`SlugFactory`]s, or given by the
        /// user.
        pub struct Slug(String);

        impl Slug {
            /// Create a `Slug` directly from a `String`. This will **not**
            /// check that the given string is compatible with the working
            /// [`SlugFactory`], and so should be used with care.
            pub fn unchecked_from_str(slug_str: String) -> Slug {
                Slug(slug_str)
            }

            pub fn inner_str<'this>(&'this self) -> &'this str {
                &self.0
            }
        }

        /// Why a provided slug is invalid.
        pub enum InvalidSlug {
            /// The slug has more characters that defined for the [`SlugFactory`].
            TooLong,
            /// The slug has a character that was not given to the [`SlugFactory`].
            BadChar,
        }

        impl SlugFactory {
            /// Create a new `SlugFactory`, according to the provided `SlugRules`.
            ///
            /// This is the preferred way to create a `SlugFactory`.
            pub fn from_rules(rules: SlugRules) -> Self {
                let mut slug_chars = BTreeSet::<char>::new();
                slug_chars.extend(rules.chars.chars());

                SlugFactory {
                    slug_length: rules.length,
                    slug_chars,
                    slug_chars_indexable: rules.chars.chars().collect(),
                }
            }

            /// Transform a literal string into a `Slug` according to the rules
            /// of this `SlugFactory`.
            ///
            /// In case the provided literal is incompatible with the
            /// `SlugFactory`'s rules, an `Err(InvalidSlug)` is provided
            /// explaining why.
            pub fn parse_str(&self, s: &str) -> Result<Slug, InvalidSlug> {
                for (i, char) in s.chars().enumerate() {
                    if i >= self.slug_length {
                        return Err(InvalidSlug::TooLong);
                    }

                    if !self.slug_chars.contains(&char) {
                        return Err(InvalidSlug::BadChar);
                    }
                }

                Ok(Slug(s.to_string()))
            }

            /// Generate a random `Slug` according to the rules of this
            /// `SlugFactory`.
            ///
            /// Internal randomness is handled by the `rand` crate, and obeys a
            /// `Uniform` distribution over the list of valid characters for
            /// each character.
            pub fn generate(&self) -> Slug {
                // Generate indices then map
                let distribution =
                    rand::distributions::Uniform::new(0, self.slug_chars_indexable.len());
                let slug_str = distribution
                    .sample_iter(rand::thread_rng())
                    .take(self.slug_length)
                    .map(|i| self.slug_chars_indexable[i])
                    .collect::<String>();
                Slug(slug_str)
            }
        }
    }
}

use service::*;

/// Shorten a URL.
async fn shorten(
    slug_factory: &slug::SlugFactory,
    db: &db::SlugDatabase,
    b64str: &str,
) -> Result<slug::Slug, (StatusCode, String)> {
    // Parse the URL given by the user. It should arrive as a Base64 string,
    // and anything other than this should cleanly result in an HTTP rejection.
    let url = {
        let unencoded_bytes = base64::decode_config(b64str, base64::STANDARD).map_err(|_| {
            (
                warp::http::StatusCode::BAD_REQUEST,
                debuginfo!("Could not decode base64 str.", "Invalid Base64.").into(),
            )
        })?;
        let url_str = std::str::from_utf8(&unencoded_bytes[..]).map_err(|_| {
            (
                warp::http::StatusCode::BAD_REQUEST,
                debuginfo!(
                    "Parsed bytes of base64 str, but could not decode as UTF8.",
                    "Invalid Base64."
                )
                .into(),
            )
        })?;
        HttpUrl::parse_string(url_str)
            .map_err(|_| (warp::http::StatusCode::BAD_REQUEST, "Invalid URL.".into()))?
            .strict()
            .map_err(|_| (warp::http::StatusCode::BAD_REQUEST, "Invalid URL.".into()))?
    };

    // Generate a (candidate) new slug for the incoming URL...
    let new_slug = slug_factory.generate();

    // ...and attempt to insert it into the database.
    // Failure to do so is reported to the user.
    let insert_result = db.insert_slug(new_slug, url).await;
    match insert_result {
        Ok(result) => match result {
            service::db::AddResult::Success(slug) => Ok(slug),
            service::db::AddResult::Fail => Err((
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                debuginfo!("Got insertion response, but it was error.").into(),
            )),
        },
        Err(e) => {
            ifdbg!(eprintln!("{}", e));
            Err((
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                debuginfo!("Response channel for insertion is unexpectedly closed").into(),
            ))
        }
    }
}

/// Redirect from a slug.
async fn redirect(
    slug_str: &str,
    slug_factory: &slug::SlugFactory,
    db: &db::SlugDatabase,
) -> Result<HttpUrl, (StatusCode, String)> {
    // Check that the slug is valid.
    let slug = slug_factory.parse_str(slug_str).map_err(|e| match e {
        slug::InvalidSlug::TooLong => (
            warp::http::StatusCode::BAD_REQUEST,
            debuginfo!("Given slug is too long.", "Invalid URL.").into(),
        ),
        slug::InvalidSlug::BadChar => (
            warp::http::StatusCode::BAD_REQUEST,
            debuginfo!("Given slug has invalid characters.", "Invalid URL.").into(),
        ),
    })?;

    match db.get_slug(slug).await {
        Ok(result) => match result {
            db::GetResult::Found(url) => Ok(url),
            db::GetResult::NotFound => Err((
                warp::http::StatusCode::BAD_REQUEST,
                debuginfo!("The slug does not exist in the database.", "Invalid URL.").into(),
            )),
            db::GetResult::InternalError => Err((
                warp::http::StatusCode::BAD_REQUEST,
                "Internal error.".into(),
            )),
        },
        Err(e) => {
            ifdbg!(eprintln!("{}", e));
            Err((
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                debuginfo!("Response channel for insertion is unexpectedly closed").into(),
            ))
        }
    }
}

#[tokio::main]
async fn serve() {
    // Read configuration

    let config: conf::Config = {
        let config_file_name = std::env::var("LONK_CONFIG").unwrap_or("lonk.json".to_string());
        let config_file = std::fs::File::open(config_file_name.clone()).unwrap_or_else(|err| {
            match err.kind() {
                std::io::ErrorKind::NotFound => {
                    panic!("Configuration file {} does not exist.", config_file_name)
                }
                std::io::ErrorKind::PermissionDenied => {
                    panic!("Read permission to {} was denied.", config_file_name)
                }
                _ => panic!(
                    "Error when trying to read configuration file {}: {}",
                    config_file_name, err
                ),
            };
        });
        let config_buf = std::io::BufReader::new(config_file);
        serde_json::from_reader(config_buf).unwrap_or_else(|err| match err.classify() {
            serde_json::error::Category::Io => panic!("IO error when reading configuration file."),
            serde_json::error::Category::Syntax => panic!(
                "Configuration file is syntactically incorrect.
                    See {}:line {}, column {}.",
                &config_file_name,
                err.line(),
                err.column()
            ),
            serde_json::error::Category::Data => panic!(
                "Error deserializing configuration file; expected different data type.
                    See {}:line {}, column {}.",
                &config_file_name,
                err.line(),
                err.column()
            ),
            serde_json::error::Category::Eof => {
                panic!("Unexpected end of file when reading configuration file.")
            }
        })
    };

    // Create slug factory
    let slug_factory = slug::SlugFactory::from_rules(config.slug_rules);

    // Initialize database
    let db = {
        let client = redis::Client::open(config.db.address).expect("Error opening Redis database.");
        db::SlugDatabase::from_client(client, config.db.expire_seconds)
    };

    // We leak the slug factory and the database, because we know that these
    // will live forever, and want them to have 'static lifetime so that warp is
    // happy.
    let slug_factory: &'static slug::SlugFactory = Box::leak(Box::new(slug_factory));
    let db: &'static db::SlugDatabase = Box::leak(Box::new(db));

    // POST /shorten/ with link in argument
    let shorten = warp::post()
        .and(warp::path("shorten"))
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::bytes())
        .then(move |body: warp::hyper::body::Bytes| async move {
            let b64str = std::str::from_utf8(&body[..]);
            if b64str.is_err() {
                return Response::builder()
                    .status(warp::http::StatusCode::BAD_REQUEST)
                    .body(String::new())
                    .unwrap();
            }
            match shorten(&slug_factory, &db, b64str.unwrap()).await {
                Ok(slug) => Response::builder()
                    .body(slug.inner_str().to_string())
                    .unwrap(),
                Err((status, message)) => Response::builder().status(status).body(message).unwrap(),
            }
        });

    // GET /l/:Slug
    let link = warp::path("l")
        .and(warp::path::param())
        .then(move |slug: String| async move {
            match redirect(&slug, &slug_factory, &db).await {
                Ok(url) => Response::builder()
                    .status(warp::http::StatusCode::FOUND)
                    .header("Location", url.to_string())
                    .body("".to_string())
                    .unwrap(),
                Err((status, message)) => Response::builder().status(status).body(message).unwrap(),
            }
        });

    // GET /
    // This should be the last thing matched, so that anything that doesn't
    //  match another filter will try to match a file.
    let homepage = warp::get().and(config.serve_rules.dir.to_filter());

    let get_routes = warp::get().and(link.or(homepage));
    let post_routes = warp::post().and(shorten);
    let routes = get_routes.or(post_routes);

    eprintln!(
        "Now serving lonk at IP {}, port {}!",
        config.serve_rules.addr.ip, config.serve_rules.addr.port
    );
    warp::serve(routes)
        .run((config.serve_rules.addr.ip, config.serve_rules.addr.port))
        .await;

    unreachable!("The warp server runs forever.")
}

#[derive(FromArgs, PartialEq, Debug)]
/// Start lonk.
struct Run {
    /// write a default configuration to stdout and quit
    #[argh(switch)]
    print_default_config: bool,
}

fn main() {
    let run = argh::from_env::<Run>();

    if run.print_default_config {
        println!(
            "{}",
            serde_json::to_string_pretty(&conf::Config::default())
                .expect("Default configuration should always be JSON serializable")
        );
    } else {
        serve();
    }
}
