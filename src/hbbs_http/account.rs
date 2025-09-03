use super::HbbHttpResponse;
use crate::hbbs_http::create_http_client;
use hbb_common::{config::LocalConfig, log, ResultType};
use reqwest::blocking::Client;
use serde_derive::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use url::Url;

lazy_static::lazy_static! {
    static ref OIDC_SESSION: Arc<RwLock<OidcSession>> = Arc::new(RwLock::new(OidcSession::new()));
}

const QUERY_INTERVAL_SECS: f32 = 1.0;
const QUERY_TIMEOUT_SECS: u64 = 60 * 3;
const REQUESTING_ACCOUNT_AUTH: &str = "Requesting account auth";
const WAITING_ACCOUNT_AUTH: &str = "Waiting account auth";
const LOGIN_ACCOUNT_AUTH: &str = "Login account auth";

#[derive(Deserialize, Clone, Debug)]
pub struct OidcAuthUrl {
    code: String,
    url: Url,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct DeviceInfo {
    /// Linux , Windows , Android ...
    #[serde(default)]
    pub os: String,

    /// `browser` or `client`
    #[serde(default)]
    pub r#type: String,

    /// device name from rustdesk client,
    /// browser info(name + version) from browser
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhitelistItem {
    data: String, // ip / device uuid
    info: DeviceInfo,
    exp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserInfo {
    #[serde(default, flatten)]
    pub settings: UserSettings,
    #[serde(default)]
    pub login_device_whitelist: Vec<WhitelistItem>,
    #[serde(default)]
    pub other: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserSettings {
    #[serde(default)]
    pub email_verification: bool,
    #[serde(default)]
    pub email_alarm_notification: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(i64)]
pub enum UserStatus {
    Disabled = 0,
    Normal = 1,
    Unverified = -1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPayload {
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub status: UserStatus,
    pub info: UserInfo,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub third_auth_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthBody {
    pub access_token: String,
    pub r#type: String,
    #[serde(default)]
    pub tfa_type: String,
    #[serde(default)]
    pub secret: String,
    pub user: UserPayload,
}

pub struct OidcSession {
    client: Client,
    state_msg: &'static str,
    failed_msg: String,
    code_url: Option<OidcAuthUrl>,
    auth_body: Option<AuthBody>,
    keep_querying: bool,
    running: bool,
    query_timeout: Duration,
}

#[derive(Serialize)]
pub struct AuthResult {
    pub state_msg: String,
    pub failed_msg: String,
    pub url: Option<String>,
    pub auth_body: Option<AuthBody>,
}

impl Default for UserStatus {
    fn default() -> Self {
        UserStatus::Normal
    }
}

impl OidcSession {
    fn new() -> Self {
        let s = Self {
            client: create_http_client(),
            state_msg: REQUESTING_ACCOUNT_AUTH,
            failed_msg: "".to_owned(),
            code_url: None,
            auth_body: None,
            keep_querying: false,
            running: false,
            query_timeout: Duration::from_secs(QUERY_TIMEOUT_SECS),
        };
        log::trace!(
            "[OIDC] OidcSession::new -> initialized with query_timeout={}s",
            QUERY_TIMEOUT_SECS
        );
        s
    }

    fn auth(
        api_server: &str,
        op: &str,
        id: &str,
        uuid: &str,
    ) -> ResultType<HbbHttpResponse<OidcAuthUrl>> {
        // Prepare request body so we can log it
        let device_info = crate::ui_interface::get_login_device_info();
        let masked_id = format!("{}*** (len={})", &id.chars().take(3).collect::<String>(), id.len());
        let masked_uuid = format!(
            "{}*** (len={})",
            &uuid.chars().take(3).collect::<String>(),
            uuid.len()
        );
        log::trace!(
            "[OIDC] auth -> POST {}/api/oidc/auth op='{}' id='{}' uuid='{}' device_info={:?}",
            api_server,
            op,
            masked_id,
            masked_uuid,
            device_info
        );
        Ok(OIDC_SESSION
            .read()
            .unwrap()
            .client
            .post(format!("{}/api/oidc/auth", api_server))
            .json(&serde_json::json!({
                "op": op,
                "id": id,
                "uuid": uuid,
                "deviceInfo": device_info,
            }))
            .send()?
            .try_into()?)
    }

    fn query(
        api_server: &str,
        code: &str,
        id: &str,
        uuid: &str,
    ) -> ResultType<HbbHttpResponse<AuthBody>> {
        let url = Url::parse_with_params(
            &format!("{}/api/oidc/auth-query", api_server),
            &[("code", code), ("id", id), ("uuid", uuid)],
        )?;
        let masked_code = format!(
            "{}*** (len={})",
            &code.chars().take(4).collect::<String>(),
            code.len()
        );
        let masked_id = format!("{}*** (len={})", &id.chars().take(3).collect::<String>(), id.len());
        let masked_uuid = format!(
            "{}*** (len={})",
            &uuid.chars().take(3).collect::<String>(),
            uuid.len()
        );
        log::trace!(
            "[OIDC] query -> GET {} (code='{}', id='{}', uuid='{}')",
            url,
            masked_code,
            masked_id,
            masked_uuid
        );
        Ok(OIDC_SESSION
            .read()
            .unwrap()
            .client
            .get(url)
            .send()?
            .try_into()?)
    }

    fn reset(&mut self) {
        self.state_msg = REQUESTING_ACCOUNT_AUTH;
        self.failed_msg = "".to_owned();
        self.keep_querying = true;
        self.running = false;
        self.code_url = None;
        self.auth_body = None;
        log::trace!("[OIDC] reset -> state='{}', keep_querying={}, running={}", self.state_msg, self.keep_querying, self.running);
    }

    fn before_task(&mut self) {
        self.reset();
        self.running = true;
        log::debug!("[OIDC] before_task -> starting auth job");
    }

    fn after_task(&mut self) {
        self.running = false;
        log::debug!("[OIDC] after_task -> auth job finished");
    }

    fn sleep(secs: f32) {
        log::trace!("[OIDC] sleep -> {}s", secs);
        std::thread::sleep(std::time::Duration::from_secs_f32(secs));
    }

    fn auth_task(api_server: String, op: String, id: String, uuid: String, remember_me: bool) {
        log::info!(
            "[OIDC] auth_task -> begin (op='{}', remember_me={}, id_len={}, uuid_len={})",
            op,
            remember_me,
            id.len(),
            uuid.len()
        );
        let auth_request_res = Self::auth(&api_server, &op, &id, &uuid);
        log::info!("[OIDC] auth_task -> auth response: {:?}", &auth_request_res);
        let code_url = match auth_request_res {
            Ok(HbbHttpResponse::<_>::Data(code_url)) => code_url,
            Ok(HbbHttpResponse::<_>::Error(err)) => {
                log::warn!("[OIDC] auth_task -> server returned error on auth: {}", err);
                OIDC_SESSION
                    .write()
                    .unwrap()
                    .set_state(REQUESTING_ACCOUNT_AUTH, err);
                return;
            }
            Ok(_) => {
                log::error!("[OIDC] auth_task -> invalid auth response variant");
                OIDC_SESSION
                    .write()
                    .unwrap()
                    .set_state(REQUESTING_ACCOUNT_AUTH, "Invalid auth response".to_owned());
                return;
            }
            Err(err) => {
                log::error!("[OIDC] auth_task -> request error: {}", err);
                OIDC_SESSION
                    .write()
                    .unwrap()
                    .set_state(REQUESTING_ACCOUNT_AUTH, err.to_string());
                return;
            }
        };

        OIDC_SESSION
            .write()
            .unwrap()
            .set_state(WAITING_ACCOUNT_AUTH, "".to_owned());
        log::debug!(
            "[OIDC] auth_task -> received code_url (code_len={}, url={})",
            code_url.code.len(),
            code_url.url
        );
        OIDC_SESSION.write().unwrap().code_url = Some(code_url.clone());

        let begin = Instant::now();
        let query_timeout = OIDC_SESSION.read().unwrap().query_timeout;
        let mut iter: u64 = 0;
        while OIDC_SESSION.read().unwrap().keep_querying && begin.elapsed() < query_timeout {
            iter += 1;
            log::trace!(
                "[OIDC] auth_task -> polling iteration={} elapsed_ms={} keep_querying={}",
                iter,
                begin.elapsed().as_millis(),
                OIDC_SESSION.read().unwrap().keep_querying
            );
            match Self::query(&api_server, &code_url.code, &id, &uuid) {
                Ok(HbbHttpResponse::<_>::Data(auth_body)) => {
                    log::debug!("[OIDC] auth_task -> query returned Data (type='{}')", auth_body.r#type);
                    if auth_body.r#type == "access_token" {
                        let token_preview = &auth_body
                            .access_token
                            .chars()
                            .take(8)
                            .collect::<String>();
                        log::info!(
                            "[OIDC] auth_task -> received access token (len={}, preview='{}***')",
                            auth_body.access_token.len(),
                            token_preview
                        );
                        if remember_me {
                            log::trace!("[OIDC] auth_task -> remember_me=true, persisting access_token and user_info");
                            LocalConfig::set_option(
                                "access_token".to_owned(),
                                auth_body.access_token.clone(),
                            );
                            LocalConfig::set_option(
                                "user_info".to_owned(),
                                serde_json::json!({ "name": auth_body.user.name, "status": auth_body.user.status }).to_string(),
                            );
                        }
                    }
                    OIDC_SESSION
                        .write()
                        .unwrap()
                        .set_state(LOGIN_ACCOUNT_AUTH, "".to_owned());
                    OIDC_SESSION.write().unwrap().auth_body = Some(auth_body);
                    log::info!("[OIDC] auth_task -> login state set, auth_body stored; finishing");
                    return;
                }
                Ok(HbbHttpResponse::<_>::Error(err)) => {
                    if err.contains("No authed oidc is found") {
                        // ignore, keep querying
                        log::trace!("[OIDC] auth_task -> not authorized yet; continuing to poll");
                    } else {
                        log::warn!("[OIDC] auth_task -> server returned error during query: {}", err);
                        OIDC_SESSION
                            .write()
                            .unwrap()
                            .set_state(WAITING_ACCOUNT_AUTH, err);
                        return;
                    }
                }
                Ok(_) => {
                    // ignore
                    log::trace!("[OIDC] auth_task -> unexpected query response variant; ignoring");
                }
                Err(err) => {
                    log::trace!("[OIDC] auth_task -> query error: {}", err);
                    // ignore
                }
            }
            Self::sleep(QUERY_INTERVAL_SECS);
        }

        if begin.elapsed() >= query_timeout {
            log::warn!(
                "[OIDC] auth_task -> polling timed out after {:?}",
                begin.elapsed()
            );
            OIDC_SESSION
                .write()
                .unwrap()
                .set_state(WAITING_ACCOUNT_AUTH, "timeout".to_owned());
        }

        // no need to handle "keep_querying == false"
    }

    fn set_state(&mut self, state_msg: &'static str, failed_msg: String) {
        log::debug!(
            "[OIDC] set_state -> {:?} (failed_msg='{}')",
            state_msg,
            failed_msg
        );
        self.state_msg = state_msg;
        self.failed_msg = failed_msg;
    }

    fn wait_stop_querying() {
        let wait_secs = 0.3;
        log::trace!("[OIDC] wait_stop_querying -> waiting for running job to finish");
        while OIDC_SESSION.read().unwrap().running {
            Self::sleep(wait_secs);
        }
        log::trace!("[OIDC] wait_stop_querying -> done");
    }

    pub fn account_auth(
        api_server: String,
        op: String,
        id: String,
        uuid: String,
        remember_me: bool,
    ) {
        log::info!(
            "[OIDC] account_auth -> requested (op='{}', id_len={}, uuid_len={}, remember_me={})",
            op,
            id.len(),
            uuid.len(),
            remember_me
        );
        Self::auth_cancel();
        Self::wait_stop_querying();
        OIDC_SESSION.write().unwrap().before_task();
        std::thread::spawn(move || {
            Self::auth_task(api_server, op, id, uuid, remember_me);
            OIDC_SESSION.write().unwrap().after_task();
        });
    }

    fn get_result_(&self) -> AuthResult {
        AuthResult {
            state_msg: self.state_msg.to_string(),
            failed_msg: self.failed_msg.clone(),
            url: self.code_url.as_ref().map(|x| x.url.to_string()),
            auth_body: self.auth_body.clone(),
        }
    }

    pub fn auth_cancel() {
        log::info!("[OIDC] auth_cancel -> stop polling requested");
        OIDC_SESSION.write().unwrap().keep_querying = false;
    }

    pub fn get_result() -> AuthResult {
        let result = OIDC_SESSION.read().unwrap().get_result_();
        log::trace!(
            "[OIDC] get_result -> state='{}', failed_msg='{}', url_present={}, auth_body_present={}",
            result.state_msg,
            result.failed_msg,
            result.url.is_some(),
            result.auth_body.is_some()
        );
        result
    }
}
