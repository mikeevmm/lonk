use std::{collections::BTreeSet, str::FromStr};

use validators::prelude::*;
use warp::{Filter, Reply};

#[derive(Debug, Validator)]
#[validator(base64_url(padding(NotAllow)))]
struct Base64WithoutPaddingUrl(String);

impl FromStr for Base64WithoutPaddingUrl {
    type Err = <Self as ValidateString>::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s)
    }
}

struct SlugParser {
    slug_length: usize,
    slug_chars: BTreeSet<char>,
}

struct Slug(String);

enum InvalidSlug {
    TooLong,
    BadChar,
}

impl SlugParser {
    fn slug_from_str(s: &str) -> Result<Slug, InvalidSlug> {
        todo!()
    }
}

async fn shorten<'s>(b64url: &'s str) -> Result<impl Reply, impl Reply> {
    let url = base64::decode_config(b64url, base64::URL_SAFE_NO_PAD).map_err(|_| {
        warp::reply::with_status(warp::reply(), warp::http::StatusCode::BAD_REQUEST)
    })?;
    todo!();
    Ok(warp::reply())
}

macro_rules! unwrap_and_err {
    ($x: ident) => {
        
    };
}

#[tokio::main]
async fn main() {
    // GET /
    let homepage = warp::path::end().and(warp::fs::file("index.html"));

    // GET /shorten/:Base64WithoutPaddingUrl
    let shorten = warp::path!("shorten" / Base64WithoutPaddingUrl)
        .map(|link: Base64WithoutPaddingUrl| shorten(&link.0));

    // GET /l/:Slug
    let link = warp::path("l")
        .and(warp::path::param())
        .map(|slug: String| warp::reply());

    let routes = warp::get().and(homepage.or(shorten).or(link));

    warp::serve(routes).run(([127, 0, 0, 1], 8892)).await;
}
