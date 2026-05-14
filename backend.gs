/**
 * 청개구리 소음진단(noise) GAS Backend v1.0
 * ================================================================
 * noise 앱 (https://anhjjeon1.github.io/noise/) 전용 백엔드.
 * 클라이언트(index.html)에서 GAS_URL로 호출. Gemini 키는 서버에만 보관.
 *
 * ── 1회 셋업 (5분) ────────────────────────────────────────────
 *  1. 새 Apps Script 프로젝트 생성: 이름 "청개구리-소음진단-Backend"
 *  2. 이 파일 전체를 Code.gs에 붙여넣기
 *  3. 좌측 ⚙️ "프로젝트 설정" → 하단 "스크립트 속성" → 다음 3개 추가:
 *       - GEMINI_API_KEY  : Google AI Studio 발급 새 Gemini 키 (noise-v2)
 *       - ADMIN_PASSWORD  : 관리자 비밀번호 (자유 설정, 8자 이상 권장)
 *       - HMAC_SECRET     : 토큰 서명용 임의 문자열 (32자 이상 무작위)
 *  4. ▶ 실행 메뉴에서 setup() 한 번 실행 → 권한 승인 (UrlFetch)
 *  5. 우상단 "배포" → "새 배포" → 유형: 웹 앱
 *       - 액세스: 모든 사용자
 *       - 다음 사용자 자격으로 실행: 나
 *     → 배포 → 웹 앱 URL 복사
 *  6. D:/noise-temp/index.html의 GAS_URL 상수를 새 URL로 교체 후 git push
 *
 * ── 보안 ──────────────────────────────────────────────────────
 *  - Gemini 키는 서버에만 저장, 클라이언트에 노출 0
 *  - 관리자 토큰은 HMAC 서명 + 24시간 만료 (stateless)
 *  - 토큰 없으면 ai 호출 거부 (handleAi unauthorized)
 * ================================================================
 */

// ───── 상수 ─────
const VERSION = 'v1.0';
const GEMINI_MODEL = 'gemini-3.1-flash-lite';
const ADMIN_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;
const SERVICE_NAME = '청개구리-소음진단-Backend';

// ───── 진입점 ─────
function doGet(e) {
  return jsonRes({ status: 'ok', service: SERVICE_NAME, version: VERSION });
}

function doPost(e) {
  let body = {};
  try {
    body = JSON.parse(e.postData.contents || '{}');
  } catch (err) {
    return jsonRes({ error: 'bad_json', message: '잘못된 요청 형식' });
  }
  const action = body.action || '';
  try {
    if (action === 'ping')        return jsonRes({ ok: true, version: VERSION });
    if (action === 'admin_auth')  return jsonRes(handleAdminAuth(body));
    if (action === 'ai')          return jsonRes(handleAi(body));
    return jsonRes({ error: 'unknown_action', valid_actions: ['ping','admin_auth','ai'] });
  } catch (err) {
    return jsonRes({ error: 'server_error', message: '서버 오류: ' + err.message });
  }
}

// ───── 핵심 액션 ─────

// 관리자 비밀번호 검증 → 24시간 HMAC 토큰 발급
function handleAdminAuth(p) {
  const pwd = String(p.pwd || '');
  const fp = String(p.fp || '');
  const expected = props_().getProperty('ADMIN_PASSWORD') || '';
  if (!expected) return { success: false, message: 'ADMIN_PASSWORD 미설정' };
  if (pwd !== expected) return { success: false, message: '비밀번호 불일치' };
  const token = makeAdminToken_(fp);
  return { success: true, token: token };
}

// AI 호출 (Gemini 프록시) — 관리자 토큰 필수
function handleAi(p) {
  const adminToken = String(p.adminToken || '');
  if (!adminToken || !verifyAdminToken_(adminToken)) {
    return { error: 'unauthorized', message: '관리자 인증 필요' };
  }

  const prompts = Array.isArray(p.prompts) ? p.prompts : [];
  if (!prompts.length) return { error: 'no_prompts', message: '프롬프트 없음' };

  const apiKey = props_().getProperty('GEMINI_API_KEY');
  if (!apiKey) return { error: 'no_api_key', message: 'GEMINI_API_KEY 미설정' };

  const url = 'https://generativelanguage.googleapis.com/v1beta/models/' + GEMINI_MODEL + ':generateContent?key=' + apiKey;
  const results = [];
  for (let i = 0; i < prompts.length; i++) {
    const item = prompts[i] || {};
    const parts = [{ text: String(item.prompt || '') }];
    const images = Array.isArray(item.images) ? item.images : [];
    images.forEach(img => {
      if (img && img.data && img.mimeType)
        parts.push({ inline_data: { mime_type: img.mimeType, data: img.data } });
    });
    const defaultConfig = { temperature: 0.15, maxOutputTokens: 8192 };
    const payload = {
      contents: [{ parts: parts }],
      generationConfig: Object.assign(defaultConfig, item.config || {})
    };
    try {
      const res = UrlFetchApp.fetch(url, {
        method: 'post',
        contentType: 'application/json',
        payload: JSON.stringify(payload),
        muteHttpExceptions: true
      });
      const code = res.getResponseCode();
      if (code !== 200) {
        results.push({ error: 'http_' + code, text: '' });
        continue;
      }
      const data = JSON.parse(res.getContentText('UTF-8'));
      const cand = (data && data.candidates && data.candidates[0]) || null;
      if (cand && cand.finishReason === 'SAFETY') {
        results.push({ error: 'safety', text: '' });
        continue;
      }
      const txt = (cand && cand.content && cand.content.parts)
        ? cand.content.parts.filter(p => !p.thought).map(p => p.text || '').join('')
        : '';
      results.push({ text: txt });
    } catch (err) {
      results.push({ error: 'fetch_failed', text: '', message: err.message });
    }
  }
  return { results: results };
}

// ───── 토큰 (HMAC) ─────

function makeAdminToken_(fp) {
  const exp = Date.now() + ADMIN_TOKEN_TTL_MS;
  const payload = fp + '|' + exp;
  const sig = hmac_(payload);
  return Utilities.base64EncodeWebSafe(payload) + '.' + sig;
}

function verifyAdminToken_(token) {
  try {
    const parts = String(token).split('.');
    if (parts.length !== 2) return false;
    const payload = Utilities.newBlob(Utilities.base64DecodeWebSafe(parts[0])).getDataAsString();
    const sigCheck = hmac_(payload);
    if (sigCheck !== parts[1]) return false;
    const exp = Number(payload.split('|')[1] || 0);
    return Date.now() < exp;
  } catch (e) { return false; }
}

function hmac_(text) {
  const secret = props_().getProperty('HMAC_SECRET') || 'CHANGE_ME';
  const sig = Utilities.computeHmacSha256Signature(text, secret);
  return Utilities.base64EncodeWebSafe(sig);
}

// ───── 유틸 ─────

function jsonRes(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

function props_() { return PropertiesService.getScriptProperties(); }

// ───── 1회 셋업 ─────
function setup() {
  const apiKey = props_().getProperty('GEMINI_API_KEY');
  const adminPwd = props_().getProperty('ADMIN_PASSWORD');
  const hmacSecret = props_().getProperty('HMAC_SECRET');
  Logger.log('=== ' + SERVICE_NAME + ' ' + VERSION + ' ===');
  Logger.log('GEMINI_API_KEY : ' + (apiKey ? 'OK (' + apiKey.substring(0,6) + '...)' : '❌ MISSING'));
  Logger.log('ADMIN_PASSWORD : ' + (adminPwd ? 'OK' : '❌ MISSING'));
  Logger.log('HMAC_SECRET    : ' + (hmacSecret ? 'OK' : '❌ MISSING'));
  try {
    UrlFetchApp.fetch('https://www.google.com', { muteHttpExceptions: true, method: 'get' });
    Logger.log('UrlFetch 권한: OK');
  } catch (e) { Logger.log('UrlFetch 권한 오류: ' + e.message); }
  return 'OK';
}
