# splunk_hec_full 改进方案

> 生成日期: 2026-04-21
> 目标: 为另一个 AI 提供精确实现指导
> 源码位置: `/Users/erenyong/Desktop/code/vector/src/sources/splunk_hec_full/`
> 文件清单: `mod.rs` (2036行), `token_binding.rs` (354行), `acknowledgements.rs` (569行)

---

## 改动总览

| # | 改动项 | 优先级 | 预估改动量 | 涉及文件 |
|---|--------|--------|-----------|----------|
| 1 | Health 端点增强: `?token=` 校验 + `?ack=` 检查 + 503 | P1 | ~80行 | mod.rs |
| 2 | Raw 端点 channel 可选 (新增配置项 `raw_require_channel`) | P1 | ~30行 | mod.rs |
| 3 | Raw 端点 `?time=` URL 参数 | P2 | ~15行 | mod.rs |
| 4 | `auto_extract_timestamp` 参数透传 | P2 | ~25行 | mod.rs |
| 5 | S2S 端点 (`/services/collector/s2s`) | P2 | ~150行 | mod.rs |

---

## 改动 1: Health 端点增强

### 背景
当前 health 端点永远返回 `200 {"text":"HEC is healthy","code":17}`，不做任何检查。
生产中 ALB/F5 负载均衡器依赖 health 端点做后端健康探测和摘除。

Splunk 原生 HEC health 端点支持:
- `GET /services/collector/health` — 检查所有 token 的队列状态
- `GET /services/collector/health?token=<token>` — 校验指定 token 有效性，无效返回 400
- `GET /services/collector/health?ack=true` — 额外检查 ACK service 健康状态
- `GET /services/collector/health?ack=true&token=<token>` — 两者组合
- 队列满时返回 503 `{"text":"HEC is unhealthy","code":15}`

### 当前代码 (mod.rs L722-L732)

```rust
fn health_service(&self) -> BoxedFilter<(Response,)> {
    warp::get()
        .and(path!("health" / "1.0").or(path!("health")))
        .map(move |_| {
            http::Response::builder()
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(hyper::Body::from(r#"{"text":"HEC is healthy","code":17}"#))
                .expect("static response")
        })
        .boxed()
}
```

### 需要改成

```rust
fn health_service(&self) -> BoxedFilter<(Response,)> {
    let valid_credentials = self.valid_credentials.clone();
    let idx_ack = self.idx_ack.clone();

    warp::get()
        .and(path!("health" / "1.0").or(path!("health")))
        .and(warp::query::<HealthQueryParams>())
        .map(move |_, params: HealthQueryParams| {
            // 1. Token validation: if ?token= is provided, validate it
            if let Some(token_val) = &params.token {
                if !valid_credentials.is_empty() {
                    let credential = format!("Splunk {}", token_val);
                    if !valid_credentials.contains(&credential) {
                        return response_json(
                            StatusCode::BAD_REQUEST,
                            serde_json::json!({"text": "Invalid token", "code": 4}),
                        );
                    }
                }
            }

            // 2. ACK service check: if ?ack=true or ?ack=1
            if params.ack_enabled() {
                match &idx_ack {
                    Some(_ack) => {
                        // ACK is configured and available — healthy
                    }
                    None => {
                        // ACK is requested but not enabled
                        return response_json(
                            StatusCode::SERVICE_UNAVAILABLE,
                            serde_json::json!({"text": "ACK is disabled", "code": 14}),
                        );
                    }
                }
            }

            // 3. Default: healthy
            response_json(
                StatusCode::OK,
                serde_json::json!({"text": "HEC is healthy", "code": 17}),
            )
        })
        .boxed()
}
```

### 新增 struct

在 `RawQueryParams` 附近添加:

```rust
/// Query parameters for the health endpoint.
#[derive(Debug, Default, Deserialize)]
struct HealthQueryParams {
    token: Option<String>,
    ack: Option<String>,
}

impl HealthQueryParams {
    /// Returns true if ack check is requested (?ack=true or ?ack=1)
    fn ack_enabled(&self) -> bool {
        self.ack.as_deref().map_or(false, |v| v == "true" || v == "1")
    }
}
```

### SplunkSource 字段传递

`health_service` 方法当前不需要 `&self`（它是一个纯函数），改动后需要访问 `self.valid_credentials` 和 `self.idx_ack`。由于这些已经存在于 `SplunkSource` struct 中，只需要在方法内 clone 即可（参考 `event_service` / `raw_service` 的模式）。

### response_json 函数

已存在于 mod.rs L1631:
```rust
fn response_json(code: StatusCode, body: impl Serialize) -> Response {
    warp::reply::with_status(warp::reply::json(&body), code).into_response()
}
```

但当前 `health_service` 返回的是 `http::Response<hyper::Body>`, 而 `response_json` 返回的是 `warp::reply::Response`。需要统一为 warp Response 类型。最简方式：将 `health_service` 的 `.map()` 改为 `.and_then()` + async block，返回 `Ok::<Response, Rejection>`。

或者更简单：继续在 `health_service` 内使用 `http::Response::builder()` 构造响应，把 body 改为 `serde_json::to_string()`。

### 关键注意

- `health_service()` 方法签名不变: `fn health_service(&self) -> BoxedFilter<(Response,)>`
- 需要在 `fn new()` 构造 `SplunkSource` 之后，`health_service` 能拿到 `valid_credentials` 和 `idx_ack`
- 这两个字段已经在 `SplunkSource` struct 中存在，直接 clone 即可

---

## 改动 2: Raw 端点 channel 可选

### 背景
当前 raw 端点**强制要求** channel，没有 channel 返回 400 "Data channel is missing"。
Splunk 原生 HEC 在 raw 端点也要求 channel，但某些旧客户端可能不传。
需加可选配置项，让用户可以放松此限制。

### 新增配置项

在 `SplunkHecFullConfig` struct 中，`fix_bare_string_events` 字段之后添加:

```rust
    /// Whether to require a channel ID on the raw endpoint.
    ///
    /// Splunk HEC requires a channel for the raw endpoint, but some legacy
    /// clients may not send one. Set to `false` to accept raw events without a channel.
    /// When false, events without a channel will have an auto-generated channel ID.
    #[serde(default = "default_true")]
    raw_require_channel: bool,
```

### Default impl 更新

在 `impl Default for SplunkHecFullConfig` 中添加:
```rust
    raw_require_channel: true,
```

### SplunkSource struct 更新

添加字段:
```rust
    raw_require_channel: bool,
```

在 `SplunkSource::new()` 中添加:
```rust
    raw_require_channel: config.raw_require_channel,
```

### raw_service() 修改

当前代码 (mod.rs 约 L595-L602):
```rust
    async move {
        // Channel: header takes priority over query param
        let channel_id = channel_header.or(query_params.channel);

        // Raw endpoint requires a channel
        let channel_id = match channel_id {
            Some(ch) => ch,
            None => return Err(Rejection::from(ApiError::MissingChannel)),
        };
```

修改为:
```rust
    let raw_require_channel = raw_require_channel; // captured from outer scope
    async move {
        // Channel: header takes priority over query param
        let channel_id = channel_header.or(query_params.channel);

        // Raw endpoint channel handling
        let channel_id = match channel_id {
            Some(ch) => ch,
            None => {
                if raw_require_channel {
                    return Err(Rejection::from(ApiError::MissingChannel));
                }
                // Auto-generate a channel ID for events without one
                uuid::Uuid::new_v4().to_string()
            }
        };
```

### 依赖

需要确认 `uuid` crate 是否已在 Cargo.toml 中。搜索方式:
```bash
grep "uuid" /Users/erenyong/Desktop/code/vector/Cargo.toml
```
如果没有，可以用其他方式生成唯一 ID（如时间戳+随机数），避免引入新依赖。Vector 项目本身很可能已依赖 uuid。

---

## 改动 3: Raw 端点 `?time=` URL 参数

### 背景
Splunk HEC raw 端点支持通过 URL 参数传递 `time`（epoch 格式时间戳），
当前 `RawQueryParams` 缺少 `time` 字段。

### RawQueryParams 修改

当前 (mod.rs L356-L365):
```rust
#[derive(Debug, Default, Deserialize)]
struct RawQueryParams {
    channel: Option<String>,
    index: Option<String>,
    sourcetype: Option<String>,
    source: Option<String>,
    host: Option<String>,
    #[allow(dead_code)]
    token: Option<String>,
}
```

改为:
```rust
#[derive(Debug, Default, Deserialize)]
struct RawQueryParams {
    channel: Option<String>,
    index: Option<String>,
    sourcetype: Option<String>,
    source: Option<String>,
    host: Option<String>,
    time: Option<String>,
    #[allow(dead_code)]
    token: Option<String>,
}
```

### raw_service() 中处理时间戳

在 raw_service 的 async block 中，在 metadata 应用逻辑之后（约 L705 附近`source_val` 处理之后），添加时间戳处理:

```rust
    // Apply time from URL query params
    if let Some(time_str) = query_params.time {
        if let Ok(time_val) = time_str.parse::<f64>() {
            let secs = time_val.floor() as i64;
            let nsecs = ((time_val.fract()) * 1_000_000_000.0) as u32;
            if let Some(timestamp) = Utc.timestamp_opt(secs, nsecs).single() {
                log_namespace.insert_source_metadata(
                    SplunkHecFullConfig::NAME,
                    log,
                    log_schema().timestamp_key().map(LegacyKey::Overwrite),
                    lookup::path!("timestamp"),
                    timestamp,
                );
            }
        }
    }
```

### 注意
- 时间戳可以是整数 (epoch seconds) 或浮点数 (epoch.millis)
- 复用已存在的 `parse_timestamp` 函数（mod.rs L1275）处理整数时间戳更好：

```rust
    if let Some(time_str) = query_params.time {
        // Try float first, then integer
        if let Ok(time_f64) = time_str.parse::<f64>() {
            let secs = time_f64.floor() as i64;
            let nsecs = ((time_f64.fract()) * 1_000_000_000.0) as u32;
            if let Some(timestamp) = Utc.timestamp_opt(secs, nsecs).single() {
                log_namespace.insert_source_metadata(
                    SplunkHecFullConfig::NAME,
                    log,
                    log_schema().timestamp_key().map(LegacyKey::Overwrite),
                    lookup::path!("timestamp"),
                    timestamp,
                );
            }
        } else if let Ok(time_i64) = time_str.parse::<i64>() {
            if let Some(timestamp) = parse_timestamp(time_i64) {
                log_namespace.insert_source_metadata(
                    SplunkHecFullConfig::NAME,
                    log,
                    log_schema().timestamp_key().map(LegacyKey::Overwrite),
                    lookup::path!("timestamp"),
                    timestamp,
                );
            }
        }
    }
```

---

## 改动 4: `auto_extract_timestamp` 参数透传

### 背景
`auto_extract_timestamp` 在 Splunk 原生 HEC 中是 **event 端点** 的 URL 查询参数：
```
POST /services/collector/event?auto_extract_timestamp=true
```
告诉 Splunk 从事件内容中自动提取时间戳。当客户端通过 Vector 代理时，需要将此参数透传到下游 sink。

### 实现评估: **简单** (约25行)

这个参数的特殊之处在于：**它不是 Vector source 需要处理的逻辑，而是需要透传给下游 Splunk sink 的指令。**

Vector 的 `splunk_hec_logs` sink 已经支持 `auto_extract_timestamp` 配置项（见 sink 代码 `logs/config.rs` L139-L148）。但那是从 sink 配置中读取的静态值。

作为代理，我们需要：
1. Source 端：从 event endpoint URL 提取 `auto_extract_timestamp` 参数
2. 写入事件的 metadata 或 event-level 字段
3. Sink 端：已有支持，会在请求 URL 中添加 `auto_extract_timestamp=true`

### 实现方案

**event_service() 中提取参数:**

在 event_service 的 warp filter chain 中，query params 已经通过 `warp::query::<HashMap<String, String>>()` 提取了 channel。可以在同一个 map 中提取 `auto_extract_timestamp`:

在 event_service 的 `and_then` async block 中（约 L490），在创建 EventIteratorGenerator 之前添加:

```rust
    // Extract auto_extract_timestamp from URL query params
    let auto_extract_ts = warp::query::<HashMap<String, String>>()
        .map(|qs: HashMap<String, String>| {
            qs.get("auto_extract_timestamp")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false)
        });
```

但实际上更简单的做法是直接作为 event-level 字段写入，让 sink 能通过模板引用:

在 event_service 的事件构建循环之后，给每个 event 打标记:

```rust
    // In the EventIterator::build_event() method, after all metadata processing,
    // before the final return:
    if self.auto_extract_timestamp {
        log.insert(event_path!("auto_extract_timestamp"), Value::from(true));
    }
```

### 修改点清单

1. **EventIteratorGenerator struct** — 添加 `auto_extract_timestamp: bool` 字段
2. **EventIterator struct** — 添加 `auto_extract_timestamp: bool` 字段
3. **EventIteratorGenerator → EventIterator 的 From impl** — 传递字段
4. **event_service()** — 从 URL query params 提取 `auto_extract_timestamp`，传入 EventIteratorGenerator
5. **EventIterator::build_event()** — 在构建事件时，如果为 true 则写入 event-level 字段

### URL 参数提取

event_service 中已有提取 channel 的模式:
```rust
let splunk_channel_query_param = warp::query::<HashMap<String, String>>()
    .map(|qs: HashMap<String, String>| qs.get("channel").map(|v| v.to_owned()));
```

同样模式提取 auto_extract_timestamp:
```rust
let auto_extract_ts_param = warp::query::<HashMap<String, String>>()
    .map(|qs: HashMap<String, String>| {
        qs.get("auto_extract_timestamp")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
    });
```

需要在 warp filter chain 中通过 `.and()` 添加这个 filter，并在 `and_then` 闭包的参数列表中接收。

**更简洁的替代方案**: 将整个 event endpoint 的 query params 统一到一个 struct（类似 RawQueryParams）:

```rust
#[derive(Debug, Default, Deserialize)]
struct EventQueryParams {
    channel: Option<String>,
    token: Option<String>,
    auto_extract_timestamp: Option<String>,
}

impl EventQueryParams {
    fn auto_extract_timestamp_enabled(&self) -> bool {
        self.auto_extract_timestamp
            .as_deref()
            .map_or(false, |v| v == "true" || v == "1")
    }
}
```

这样可以替换现有的两个独立 query param 提取器 (channel + token)，简化代码。

---

## 改动 5: S2S 端点

### 背景
`/services/collector/s2s` 用于接收 Splunk Universal Forwarder (UF) 通过 HTTP 传输的 S2S (Splunk-to-Splunk) 格式数据。

- Splunk Enterprise 8.1.0+ 支持
- UF 通过 `[httpout]` stanza 配置，将原本走 TCP 9997 的数据改为通过 HTTP POST 发送到 HEC 端口
- 数据格式：**不是 JSON**，而是 Splunk 私有的二进制 S2S 协议包装在 HTTP body 中

### 重要发现
Vector 整个代码库中 **没有任何 S2S 相关实现**。这是一个全新的端点。

### S2S 协议分析

S2S over HTTP 的数据格式：
1. HTTP POST body 包含 Splunk 私有的 S2S 协议帧
2. Content-Type 通常为 `application/octet-stream`
3. S2S 帧格式：
   - 4 字节: 签名 (magic number)
   - 4 字节: 数据长度
   - N 字节: 序列化的 Splunk 事件数据（包含 _raw, host, source, sourcetype, index, _time 等字段）
4. 认证使用标准 HEC token (`Authorization: Splunk <token>`)

### 实现方案: 两种选择

#### 方案 A: 完整 S2S 协议解析 (复杂，不推荐)
需要逆向工程 Splunk S2S 二进制协议，工作量大且协议可能随版本变化。

#### 方案 B: S2S 透传代理 (推荐)
**不解析 S2S 数据包内容**，而是将整个 HTTP body 作为 raw bytes 透传到下游 Splunk。
这与你的 "透传" 场景完全匹配。

```rust
fn s2s_service(&self, out: SourceSender) -> BoxedFilter<(Response,)> {
    let protocol = self.protocol;
    let store_hec_token = self.store_hec_token;
    let events_received = self.events_received.clone();
    let log_namespace = self.log_namespace;

    warp::post()
        .and(path!("s2s"))
        .and(self.authorization())
        .and(warp::addr::remote())
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(self.gzip())
        .and(warp::body::bytes())
        .and(warp::path::full())
        .and_then(
            move |token: Option<String>,
                  remote: Option<SocketAddr>,
                  xff: Option<String>,
                  gzip: bool,
                  body: Bytes,
                  path: warp::path::FullPath| {
                let mut out = out.clone();
                let events_received = events_received.clone();

                emit!(HttpBytesReceived {
                    byte_size: body.len(),
                    http_path: path.as_str(),
                    protocol,
                });

                async move {
                    // Decompress if gzipped
                    let data: Bytes = if gzip {
                        let mut buf = Vec::new();
                        MultiGzDecoder::new(body.reader())
                            .read_to_end(&mut buf)
                            .map_err(|_| Rejection::from(ApiError::BadRequest))?;
                        Bytes::from(buf)
                    } else {
                        body
                    };

                    if data.is_empty() {
                        return Err(Rejection::from(ApiError::NoData));
                    }

                    // Build a log event with the raw S2S payload
                    let mut log = match log_namespace {
                        LogNamespace::Vector => LogEvent::from(Value::from(data)),
                        LogNamespace::Legacy => {
                            let mut l = LogEvent::default();
                            l.maybe_insert(
                                log_schema().message_key_target_path(),
                                Value::from(data),
                            );
                            l
                        }
                    };

                    events_received.emit(CountByteSize(
                        1,
                        log.estimated_json_encoded_size_of(),
                    ));

                    // Mark as S2S format for downstream routing
                    log.insert(event_path!("_s2s"), Value::from(true));
                    log.insert(event_path!("_s2s_content_type"), Value::from("application/octet-stream"));

                    // Host from XFF or remote addr
                    let host = xff.or_else(|| remote.map(|r| r.to_string()));
                    if let Some(host_val) = host {
                        log_namespace.insert_source_metadata(
                            SplunkHecFullConfig::NAME,
                            &mut log,
                            log_schema().host_key().map(LegacyKey::InsertIfEmpty),
                            lookup::path!("host"),
                            host_val,
                        );
                    }

                    log_namespace.insert_standard_vector_source_metadata(
                        &mut log,
                        SplunkHecFullConfig::NAME,
                        Utc::now(),
                    );

                    log_namespace.insert_vector_metadata(
                        &mut log,
                        log_schema().source_type_key(),
                        &owned_value_path!("source_type"),
                        SplunkHecFullConfig::NAME,
                    );

                    // Store HEC token for passthrough
                    if let Some(tok) = token.filter(|_| store_hec_token) {
                        log.metadata_mut().set_splunk_hec_token(tok.into());
                    }

                    let event = Event::from(log);
                    out.send_event(event)
                        .await
                        .map(|_| None) // No ackId for S2S
                        .map_err(|_| Rejection::from(ApiError::ServerShutdown))
                }
            },
        )
        .map(finish_ok)
        .boxed()
}
```

### 路由注册

在 `build()` 方法中（mod.rs 约 L227），添加 s2s_service:

当前:
```rust
let event_service = source.event_service(out.clone());
let raw_service = source.raw_service(out);
let health_service = source.health_service();
let ack_service = source.ack_service();
let options = SplunkSource::options();
```

改为:
```rust
let event_service = source.event_service(out.clone());
let raw_service = source.raw_service(out.clone());
let s2s_service = source.s2s_service(out);
let health_service = source.health_service();
let ack_service = source.ack_service();
let options = SplunkSource::options();
```

当前路由组合:
```rust
let services = path!("services" / "collector" / ..)
    .and(
        event_service
            .or(raw_service)
            .unify()
            .or(health_service)
            .unify()
            .or(ack_service)
            .unify()
            .or(options)
            .unify(),
    )
    .or_else(finish_err);
```

改为:
```rust
let services = path!("services" / "collector" / ..)
    .and(
        event_service
            .or(raw_service)
            .unify()
            .or(s2s_service)
            .unify()
            .or(health_service)
            .unify()
            .or(ack_service)
            .unify()
            .or(options)
            .unify(),
    )
    .or_else(finish_err);
```

### OPTIONS 支持

在 `SplunkSource::options()` 方法中，为 s2s 路径添加 OPTIONS:

当前:
```rust
fn options() -> BoxedFilter<(Response,)> {
    let post = warp::options()
        .and(
            path!("event")
                .or(path!("event" / "1.0"))
                .or(path!("raw" / "1.0"))
                .or(path!("raw")),
        )
        .map(|_| warp::reply::with_header(warp::reply(), "Allow", "POST").into_response());
    // ...
}
```

改为:
```rust
fn options() -> BoxedFilter<(Response,)> {
    let post = warp::options()
        .and(
            path!("event")
                .or(path!("event" / "1.0"))
                .or(path!("raw" / "1.0"))
                .or(path!("raw"))
                .or(path!("s2s")),
        )
        .map(|_| warp::reply::with_header(warp::reply(), "Allow", "POST").into_response());
    // ...
}
```

### 下游 Sink 注意

S2S 数据透传时，下游 sink 需要把 raw body 原封不动发到 Splunk 的 `/services/collector/s2s`。
这需要一个支持 S2S 的 sink 配置，或者现有的 `splunk_hec_logs` sink 添加 `endpoint_target: s2s` 选项。

**临时替代方案:** 如果不想改 sink，可以用 `http` sink 做 S2S 透传:

```yaml
sinks:
  snk_s2s_passthrough:
    type: http
    inputs: ["route_s2s"]
    uri: "https://splunkhec.example.com:8088/services/collector/s2s"
    method: post
    encoding:
      codec: raw_message
    headers:
      Authorization: "Splunk {{ splunk_hec_token }}"
      Content-Type: "application/octet-stream"
```

但更优雅的方式是在 `splunk_hec_logs` sink 中添加 `EndpointTarget::S2S` variant。这属于 sink 侧改动，不在本次 source 改进范围内，可后续迭代。

---

## 改动间依赖关系

```
改动 1 (Health)    — 独立，无依赖
改动 2 (Channel)   — 独立，无依赖
改动 3 (Raw time)  — 独立，无依赖
改动 4 (AutoExtTS) — 独立，无依赖
改动 5 (S2S)       — 独立，但下游 sink 配合需要另外处理
```

所有改动互不依赖，可以并行实现。

---

## 单元测试要求

每个改动需配套单元测试，添加在 `mod.rs` 末尾 `#[cfg(test)] mod tests` 中。

### 改动 1 测试

```rust
#[tokio::test]
async fn test_health_with_valid_token() {
    let (_source, address, _guard) = source().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{address}/services/collector/health?token={TOKEN}"))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_health_with_invalid_token() {
    let (_source, address, _guard) = source().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{address}/services/collector/health?token=bad-token"))
        .send().await.unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_health_with_ack_disabled() {
    let (_source, address, _guard) = source().await; // default: ack disabled
    let resp = reqwest::Client::new()
        .get(format!("http://{address}/services/collector/health?ack=true"))
        .send().await.unwrap();
    assert_eq!(resp.status(), 503);
}

#[tokio::test]
async fn test_health_no_params() {
    let (_source, address, _guard) = source().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{address}/services/collector/health"))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], 17);
}
```

### 改动 2 测试

```rust
#[tokio::test]
async fn test_raw_without_channel_required() {
    // Default: raw_require_channel = true
    let (_source, address, _guard) = source().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{address}/services/collector/raw"))
        .header("Authorization", format!("Splunk {TOKEN}"))
        .body("raw data without channel")
        .send().await.unwrap();
    assert_eq!(resp.status(), 400); // Missing channel
}

#[tokio::test]
async fn test_raw_without_channel_optional() {
    // raw_require_channel = false (need new source_with variant)
    // ... create source with raw_require_channel=false ...
    // Send without channel should succeed
}
```

### 改动 3 测试

```rust
#[tokio::test]
async fn test_raw_endpoint_time_param() {
    let (source, address, _guard) = source().await;
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{address}/services/collector/raw?channel=ch1&time=1609459200"
        ))
        .header("Authorization", format!("Splunk {TOKEN}"))
        .body("event with time")
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let events = collect_n(source, 1).await;
    let log = events[0].as_log();
    // Verify timestamp was set to 2021-01-01T00:00:00Z
    let ts = log.get("timestamp").unwrap();
    // assert timestamp matches epoch 1609459200
}

#[tokio::test]
async fn test_raw_endpoint_time_param_float() {
    // Test with float timestamp like 1609459200.123
}
```

### 改动 4 测试

```rust
#[tokio::test]
async fn test_event_auto_extract_timestamp_param() {
    let (source, address, _guard) = source().await;
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{address}/services/collector/event?auto_extract_timestamp=true"
        ))
        .header("Authorization", format!("Splunk {TOKEN}"))
        .header("x-splunk-request-channel", "ch1")
        .body(r#"{"event":"test auto extract"}"#)
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let events = collect_n(source, 1).await;
    let log = events[0].as_log();
    assert_eq!(
        log.get("auto_extract_timestamp").unwrap().to_string_lossy(),
        "true"
    );
}
```

### 改动 5 测试

```rust
#[tokio::test]
async fn test_s2s_endpoint_basic() {
    let (source, address, _guard) = source().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{address}/services/collector/s2s"))
        .header("Authorization", format!("Splunk {TOKEN}"))
        .header("Content-Type", "application/octet-stream")
        .body(b"\x00\x01\x02\x03binary s2s data".to_vec())
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let events = collect_n(source, 1).await;
    let log = events[0].as_log();
    assert_eq!(log.get("_s2s").unwrap().to_string_lossy(), "true");
}

#[tokio::test]
async fn test_s2s_endpoint_no_auth() {
    let (_source, address, _guard) = source().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{address}/services/collector/s2s"))
        .header("Content-Type", "application/octet-stream")
        .body(b"no auth".to_vec())
        .send().await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_s2s_endpoint_empty_body() {
    let (_source, address, _guard) = source().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{address}/services/collector/s2s"))
        .header("Authorization", format!("Splunk {TOKEN}"))
        .body(b"".to_vec())
        .send().await.unwrap();
    assert_eq!(resp.status(), 400); // NoData
}

#[tokio::test]
async fn test_s2s_token_passthrough() {
    let (source, address, _guard) = source_with(
        Some(TOKEN.to_owned().into()), None, None, true, HashMap::new(),
    ).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{address}/services/collector/s2s"))
        .header("Authorization", format!("Splunk {TOKEN}"))
        .body(b"s2s with token".to_vec())
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let events = collect_n(source, 1).await;
    let log = events[0].as_log();
    assert_eq!(log.metadata().splunk_hec_token().unwrap().as_ref(), TOKEN);
}
```

---

## 编译验证

每个改动完成后执行:
```bash
cd /Users/erenyong/Desktop/code/vector
cargo check -p vector --lib 2>&1 | head -50
cargo test --lib sources::splunk_hec_full 2>&1
```

全部改动完成后执行完整测试:
```bash
cargo test --lib sources::splunk_hec_full -- --nocapture 2>&1
```

---

## source_with 测试辅助函数扩展

当前 `source_with` 签名:
```rust
async fn source_with(
    token: Option<SensitiveString>,
    valid_tokens: Option<&[&str]>,
    acknowledgements: Option<HecAcknowledgementsConfig>,
    store_hec_token: bool,
    token_bindings: HashMap<String, TokenBindingConfig>,
) -> (impl Stream<Item = Event> + Unpin, SocketAddr, PortGuard)
```

需要扩展为接受新参数 (`raw_require_channel`)。**建议**: 不改变现有签名，新增一个 `source_with_full` 函数:

```rust
async fn source_with_full(
    token: Option<SensitiveString>,
    valid_tokens: Option<&[&str]>,
    acknowledgements: Option<HecAcknowledgementsConfig>,
    store_hec_token: bool,
    token_bindings: HashMap<String, TokenBindingConfig>,
    raw_require_channel: bool,
) -> (impl Stream<Item = Event> + Unpin, SocketAddr, PortGuard) {
    // ... same as source_with but with raw_require_channel parameter
}
```

---

## 总结

| 改动 | 文件 | 新增行数 | 修改行数 | 新增测试 |
|------|------|---------|---------|---------|
| 1. Health 增强 | mod.rs | ~50 | ~15 | 4 |
| 2. Channel 可选 | mod.rs | ~20 | ~10 | 2 |
| 3. Raw ?time= | mod.rs | ~15 | ~2 | 2 |
| 4. auto_extract_ts | mod.rs | ~20 | ~5 | 1 |
| 5. S2S 端点 | mod.rs | ~120 | ~10 | 4 |
| **合计** | | **~225** | **~42** | **13** |
