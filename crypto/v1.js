import * as vodozemac from "../vendor/vodozemac/0.1.0/vodozemac_bg.js"

const subtle = globalThis.crypto.subtle
const encoder = new TextEncoder()

export const PROTOCOL = 1
export const WASM_SHA256 = "5b3a606864bbcfe31f4e91f12e73b659c494f6d13c36cb6e1ec94dce992410fd"

const OLM = "/users/api/v1/olm"
const PREFIX = new URL(import.meta.url).pathname.replace(/\/static\/js\/chat\.js$/, "")
const BIND = "users-olm-bind-v1"
const SIGNING = "users-olm-signing-v1"
const ROOM_KEY = "users-chat/room-key"
const MESSAGE = "users-chat/message"
const PKCS8_ED25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])
const MIN_KEYS = 20
const KEY_BATCH = 40
const PEER_SESSIONS = 4
const SEEN_LIMIT = 2000
const ROTATE_MESSAGES = 100
const ROTATE_AGE = 7 * 24 * 3600 * 1000
const LIST_TTL = 60000
const NAME_LENGTH = 64

let ready = null


export class ChatError extends Error {
    constructor(code) {
        super(code)
        this.code = code
    }
}

function concat(...parts) {
    const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0))
    let offset = 0
    for (const part of parts) {
        out.set(part, offset)
        offset += part.length
    }
    return out
}

export function b64(bytes) {
    let binary = ""
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/=+$/, "")
}

export function fromB64(text) {
    const value = String(text).replace(/-/g, "+").replace(/_/g, "/")
    const binary = atob(value + "=".repeat((4 - value.length % 4) % 4))
    return Uint8Array.from(binary, char => char.charCodeAt(0))
}

export function b64url(bytes) {
    return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_")
}

export const fromB64url = fromB64

export function randomId(length = 16) {
    return b64url(globalThis.crypto.getRandomValues(new Uint8Array(length)))
}

async function hex(bytes) {
    return Array.from(new Uint8Array(await subtle.digest("SHA-256", bytes)), byte => byte.toString(16).padStart(2, "0")).join("")
}

async function digest16(bytes) {
    return b64url(new Uint8Array(await subtle.digest("SHA-256", bytes)).slice(0, 16))
}

export const fingerprint = key => digest16(fromB64url(key))
export const keyFingerprint = key => digest16(fromB64(key))

export async function verify(publicKey, context, payload, signature, canonical) {
    try {
        const key = await subtle.importKey("raw", fromB64url(publicKey), { name: "Ed25519" }, false, ["verify"])
        return await subtle.verify({ name: "Ed25519" }, key, fromB64url(signature), encoder.encode(`${context}\n${canonical(payload)}`))
    } catch {
        return false
    }
}

export async function signer(seed, canonical) {
    const pkcs8 = concat(PKCS8_ED25519, seed)
    const exportable = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"])
    const publicKey = (await subtle.exportKey("jwk", exportable)).x
    const key = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"])
    return {
        publicKey,
        async sign(context, payload) {
            const signature = await subtle.sign({ name: "Ed25519" }, key, encoder.encode(`${context}\n${canonical(payload)}`))
            return b64url(new Uint8Array(signature))
        }
    }
}

export async function verifyDevice(record, canonical) {
    const binding = record?.binding ?? {}
    if (binding.ctx !== BIND || binding.account !== record.account || binding.device !== record.device
        || binding.curve25519 !== record.curve25519 || binding.ed25519 !== record.ed25519
        || typeof record.device_key !== "string") return false
    if (record.kind === "browser") {
        const signing = record.signing
        const anchor = signing?.binding ?? {}
        if (binding.kind !== "browser" || anchor.ctx !== SIGNING || anchor.account !== record.account
            || anchor.signing !== signing.signing || anchor.device !== await fingerprint(record.device_key)) return false
        if (await keyFingerprint(record.ed25519) !== record.device) return false
        return await verify(record.device_key, SIGNING, anchor, signing.signature, canonical)
            && await verify(signing.signing, BIND, binding, record.signature, canonical)
    }
    if (record.kind !== "app" || "kind" in binding) return false
    if (await fingerprint(record.device_key) !== record.device) return false
    return verify(record.device_key, BIND, binding, record.signature, canonical)
}

function name(value) {
    return typeof value === "string" && value.trim() ? value.trim().slice(0, NAME_LENGTH) : null
}

export function card(value) {
    const first = name(value?.first)
    return first ? { first, last: name(value?.last) } : null
}

export function load(wasm) {
    ready ??= (async () => {
        const bytes = wasm ?? await fetch(new URL("../vendor/vodozemac/0.1.0/vodozemac_bg.wasm", import.meta.url),
            { credentials: "same-origin" }).then(response => {
            if (!response.ok) throw new ChatError("CRYPTO_UNAVAILABLE")
            return response.arrayBuffer()
        })
        if (await hex(bytes) !== WASM_SHA256) throw new ChatError("CRYPTO_MISMATCH")
        const { instance } = await WebAssembly.instantiate(bytes, { "./vodozemac_bg.js": vodozemac })
        vodozemac.__wbg_set_wasm(instance.exports)
        instance.exports.__wbindgen_start()
        return vodozemac
    })().catch(error => {
        ready = null
        throw error
    })
    return ready
}

export function idbStore(database = "users-chat", store = "state") {
    const open = () => new Promise((resolve, reject) => {
        const request = indexedDB.open(database, 1)
        request.onupgradeneeded = () => request.result.createObjectStore(store)
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
    })
    const run = async (mode, work) => {
        const db = await open()
        try {
            return await new Promise((resolve, reject) => {
                const transaction = db.transaction(store, mode)
                const request = work(transaction.objectStore(store))
                transaction.oncomplete = () => resolve(request?.result)
                transaction.onerror = () => reject(transaction.error)
                transaction.onabort = () => reject(transaction.error)
            })
        } finally {
            db.close()
        }
    }
    return {
        get: key => run("readonly", objects => objects.get(key)),
        set: (key, value) => run("readwrite", objects => objects.put(value, key)).then(() => undefined),
        del: key => run("readwrite", objects => objects.delete(key)).then(() => undefined)
    }
}

export class ChatCrypto {
    constructor(ctx, olm, pickleKey, sealedKey, state, device) {
        this.ctx = ctx
        this.vz = ctx.vz
        this.prefix = ctx.prefix ?? PREFIX
        this.olm = olm
        this.pickleKey = pickleKey
        this.sealedKey = sealedKey
        this.sessions = state.sessions
        this.seen = state.seen
        this.pins = state.pins
        this.notices = state.notices
        this.device = device
        this.identity = olm.ed25519_key
        this.outbound = new Map()
        this.inbound = new Map()
        this.lists = new Map()
        this.signingCache = null
        this.created = 0
        this.queue = Promise.resolve()
    }

    static storeKey(user) {
        return `device:${user}`
    }

    static async open(ctx) {
        const key = ChatCrypto.storeKey(ctx.user)
        const record = await ctx.store.get(key).catch(() => null)
        if (record?.v === PROTOCOL && record.account === ctx.account) {
            try {
                const pickleKey = fromB64url(await ctx.sealer.decrypt(record.key))
                const olm = ctx.vz.Account.from_pickle(record.olm, pickleKey)
                const sessions = new Map(Object.entries(record.sessions ?? {}).map(([peer, items]) =>
                    [peer, items.map(item => ctx.vz.Session.from_pickle(item, pickleKey))]))
                const state = { sessions, seen: record.seen ?? [], pins: record.pins ?? {}, notices: record.notices ?? {} }
                return new ChatCrypto(ctx, olm, pickleKey, record.key, state, await keyFingerprint(olm.ed25519_key))
            } catch {
                await ctx.store.del(key).catch(() => null)
            }
        }
        const pickleKey = globalThis.crypto.getRandomValues(new Uint8Array(32))
        const olm = new ctx.vz.Account()
        const state = { sessions: new Map(), seen: [], pins: {}, notices: {} }
        const crypto = new ChatCrypto(ctx, olm, pickleKey, await ctx.sealer.encrypt(b64url(pickleKey)), state,
            await keyFingerprint(olm.ed25519_key))
        await crypto.save()
        return crypto
    }

    serial(work) {
        const run = this.queue.then(work, work)
        this.queue = run.catch(() => null)
        return run
    }

    async save() {
        await this.ctx.store.set(ChatCrypto.storeKey(this.ctx.user), {
            v: PROTOCOL, account: this.ctx.account, key: this.sealedKey, olm: this.olm.pickle(this.pickleKey),
            sessions: Object.fromEntries([...this.sessions].map(([peer, items]) => [peer, items.map(item => item.pickle(this.pickleKey))])),
            seen: this.seen.slice(-SEEN_LIMIT), pins: this.pins, notices: this.notices
        })
    }

    self() {
        return { account: this.ctx.account, device: this.device, ed25519: this.identity }
    }

    async signing() {
        if (this.signingCache) return this.signingCache
        const data = await this.ctx.http.get(`${OLM}/signing`)
        if (!data?.current) throw new ChatError("SIGNING_KEY_STALE")
        const created = await signer(fromB64url(await this.ctx.sealer.decrypt(data.secret)), this.ctx.canonical)
        if (created.publicKey !== data.signing) throw new ChatError("SIGNING_KEY_MISMATCH")
        return this.signingCache = created
    }

    unpublished() {
        const keys = this.olm.one_time_keys
        return keys instanceof Map ? Object.fromEntries(keys) : { ...(keys ?? {}) }
    }

    async publishNow() {
        const sign = await this.signing()
        const binding = {
            ctx: BIND, account: this.ctx.account, device: this.device, curve25519: this.olm.curve25519_key,
            ed25519: this.identity, kind: "browser", ts: Math.floor(Date.now() / 1000)
        }
        const signature = await sign.sign(BIND, binding)
        const post = async () => {
            const answer = await this.ctx.http.post(`${OLM}/keys`, { binding, signature, one_time_keys: this.unpublished() })
            this.olm.mark_keys_as_published()
            return answer
        }
        let answer = await post()
        if ((answer?.stored ?? 0) < MIN_KEYS) {
            this.olm.generate_one_time_keys(KEY_BATCH).free()
            answer = await post()
        }
        this.created = 0
        await this.save()
        return answer
    }

    publish() {
        return this.serial(() => this.publishNow())
    }

    async claim(account, keys) {
        const query = new URLSearchParams({ exclude: this.device })
        if (keys) query.set("keys", keys.join(","))
        return this.ctx.http.post(`${OLM}/devices/${encodeURIComponent(account)}/claim?${query}`)
    }

    async trust(account, deviceKey) {
        if (typeof deviceKey !== "string" || !deviceKey) return false
        const verdict = this.ctx.verifyKey ? await this.ctx.verifyKey(account, deviceKey).catch(() => "unknown") : "unknown"
        if (verdict === "conflict") return false
        const pinned = this.pins[account]
        if (pinned !== deviceKey) {
            if (pinned) this.notices[account] = Date.now()
            this.pins[account] = deviceKey
            await this.save()
        }
        return true
    }

    notice(account) {
        return this.notices[account] ?? null
    }

    async acknowledge(account) {
        if (!(account in this.notices)) return
        delete this.notices[account]
        await this.save()
    }

    async accept(account, claim) {
        if (!claim || claim.account !== account || !await this.trust(account, claim.device_key)) return []
        const out = []
        for (const record of claim.devices ?? []) {
            if (record.account !== account || record.device === this.device || record.device_key !== claim.device_key) continue
            if (await verifyDevice(record, this.ctx.canonical)) out.push(record)
        }
        return out
    }

    async devices(account, fresh = false) {
        const cached = this.lists.get(account)
        if (!fresh && cached && Date.now() - cached.at < LIST_TTL) return cached.devices
        const devices = await this.accept(account, await this.claim(account, []))
        this.lists.set(account, { at: Date.now(), devices })
        return devices
    }

    address(record) {
        return `${record.account}/${record.device}`
    }

    encryptFor(record, plaintext) {
        const address = this.address(record)
        let sessions = this.sessions.get(address)
        if (!sessions?.length) {
            if (!record.one_time_key?.key) throw new ChatError("NO_ONE_TIME_KEY")
            sessions = [this.olm.create_outbound_session(record.curve25519, record.one_time_key.key, this.vz.SessionConfigVersion.V1)]
            this.sessions.set(address, sessions)
        }
        const message = sessions[0].encrypt(plaintext)
        const out = { type: message.message_type, body: b64(message.ciphertext) }
        message.free()
        return out
    }

    decryptFrom(sender, type, body) {
        const address = this.address(sender)
        const sessions = this.sessions.get(address) ?? []
        const bytes = fromB64(body)
        for (let index = 0; index < sessions.length; index++) {
            const message = new this.vz.OlmMessage(type, bytes)
            try {
                const plaintext = sessions[index].decrypt(message)
                if (index) sessions.unshift(...sessions.splice(index, 1))
                return plaintext
            } catch {
                continue
            } finally {
                message.free()
            }
        }
        if (type !== 0) throw new ChatError("NO_MATCHING_SESSION")
        const message = new this.vz.OlmMessage(type, bytes)
        try {
            const created = this.olm.create_inbound_session(sender.curve25519, message)
            const plaintext = created.plaintext
            sessions.unshift(created.session)
            while (sessions.length > PEER_SESSIONS) sessions.pop().free()
            this.sessions.set(address, sessions)
            this.created += 1
            return plaintext
        } finally {
            message.free()
        }
    }

    async share(room, out) {
        for (const account of room.members) {
            const devices = await this.devices(account)
            if (account !== this.ctx.account && !devices.length) throw new ChatError("NO_DEVICES")
            const pending = devices.filter(record => !out.shared.has(this.address(record)))
            if (!pending.length) continue
            const missing = pending.filter(record => !this.sessions.get(this.address(record))?.length).map(record => record.device)
            let targets = pending
            if (missing.length) {
                const fresh = await this.accept(account, await this.claim(account, missing))
                targets = pending.map(record => fresh.find(item => item.device === record.device) ?? record)
            }
            for (const record of targets) {
                const payload = {
                    t: ROOM_KEY, v: PROTOCOL, room: room.id, session_id: out.session.session_id,
                    session_key: out.session.session_key, sender: this.self(),
                    recipient: { account: record.account, device: record.device }
                }
                try {
                    const message = this.encryptFor(record, JSON.stringify(payload))
                    await this.ctx.http.post(`${OLM}/messages`, {
                        account: record.account, device: record.device, message_id: randomId(16),
                        type: message.type, body: message.body, sender: this.device
                    })
                    out.shared.add(this.address(record))
                } catch (error) {
                    if (error?.code !== "NO_ONE_TIME_KEY" && error?.status !== 404) throw error
                }
            }
        }
        await this.save()
    }

    encrypt(room, body, sender) {
        return this.serial(async () => {
            let out = this.outbound.get(room.id)
            if (!out || out.count >= ROTATE_MESSAGES || Date.now() - out.created > ROTATE_AGE) {
                out?.session.free()
                const session = new this.vz.GroupSession(this.vz.GroupSessionVersion.V1)
                out = { session, shared: new Set(), created: Date.now(), count: 0 }
                this.outbound.set(room.id, out)
                const inbound = new this.vz.InboundGroupSession(session.session_key, this.vz.GroupSessionVersion.V1)
                const entry = { session: inbound, room: room.id, sender: this.self() }
                this.inbound.set(session.session_id, entry)
                await this.backup(room.id, session.session_id, entry)
            }
            await this.share(room, out)
            const plain = {
                t: MESSAGE, v: PROTOCOL, room: room.id, body, ts: Date.now(),
                from: { account: this.ctx.account, device: this.device }, card: card(sender)
            }
            const ciphertext = out.session.encrypt(JSON.stringify(plain))
            out.count += 1
            return { device: this.device, session_id: out.session.session_id, ciphertext }
        })
    }

    async roomKey(sender, plaintext) {
        let data
        try {
            data = JSON.parse(plaintext)
        } catch {
            return false
        }
        if (data?.t !== ROOM_KEY || data.v !== PROTOCOL) return false
        if (data.recipient?.account !== this.ctx.account || data.recipient?.device !== this.device) return false
        const from = data.sender ?? {}
        if (from.account !== sender.account || from.device !== sender.device || from.ed25519 !== sender.ed25519) return false
        if (typeof data.room !== "string" || typeof data.session_id !== "string" || typeof data.session_key !== "string") return false
        let session
        try {
            session = new this.vz.InboundGroupSession(data.session_key, this.vz.GroupSessionVersion.V1)
        } catch {
            return false
        }
        const existing = this.inbound.get(data.session_id)
        if (session.session_id !== data.session_id || (existing && (existing.room !== data.room
            || existing.sender.account !== from.account || existing.sender.device !== from.device
            || existing.session.first_known_index <= session.first_known_index))) {
            session.free()
            return false
        }
        existing?.session.free()
        const entry = { session, room: data.room, sender: { account: from.account, device: from.device, ed25519: from.ed25519 } }
        this.inbound.set(data.session_id, entry)
        await this.backup(data.room, data.session_id, entry)
        return true
    }

    receive() {
        return this.serial(async () => {
            const data = await this.ctx.http.get(`${OLM}/messages?device=${encodeURIComponent(this.device)}`)
            const ids = []
            let keys = 0
            for (const item of data?.messages ?? []) {
                ids.push(item.id)
                const sender = item.sender
                const mark = `${sender?.account}/${sender?.device}#${item.message_id}`
                if (!sender || this.seen.includes(mark)) continue
                this.seen.push(mark)
                if (!await verifyDevice(sender, this.ctx.canonical) || !await this.trust(sender.account, sender.device_key)) continue
                let plaintext
                try {
                    plaintext = this.decryptFrom(sender, item.type, item.body)
                } catch {
                    continue
                }
                if (await this.roomKey(sender, plaintext)) keys += 1
            }
            if (this.seen.length > SEEN_LIMIT) this.seen = this.seen.slice(-SEEN_LIMIT)
            await this.save()
            if (ids.length) await this.ctx.http.post(`${OLM}/messages/ack`, { ids })
            if (this.created) await this.publishNow()
            return keys
        })
    }

    async backup(room, sessionId, entry) {
        const index = entry.session.first_known_index
        const key = entry.session.export_at(index)
        if (!key) return
        const data = await this.ctx.sealer.encrypt(JSON.stringify({
            v: PROTOCOL, room, session_id: sessionId, key, first_index: index, sender: entry.sender
        }))
        await this.ctx.http.put(`${this.prefix}/api/v1/keys`, { keys: [{ room, session_id: sessionId, first_index: index, data }] })
            .catch(() => null)
    }

    async restore(room, ids) {
        if (!ids.length) return
        const query = ids.map(id => `session=${encodeURIComponent(id)}`).join("&")
        const data = await this.ctx.http.get(`${this.prefix}/api/v1/rooms/${encodeURIComponent(room)}/keys?${query}`).catch(() => null)
        for (const item of data?.keys ?? []) {
            try {
                const record = JSON.parse(await this.ctx.sealer.decrypt(item.data))
                if (record.v !== PROTOCOL || record.room !== room || record.session_id !== item.session_id) continue
                const existing = this.inbound.get(item.session_id)
                if (existing && existing.session.first_known_index <= record.first_index) continue
                const session = this.vz.InboundGroupSession.import(record.key, this.vz.GroupSessionVersion.V1)
                if (session.session_id !== item.session_id) {
                    session.free()
                    continue
                }
                existing?.session.free()
                this.inbound.set(item.session_id, { session, room, sender: record.sender ?? {} })
            } catch {
                continue
            }
        }
    }

    open(room, event) {
        const base = { seq: event.seq, sender: event.sender, created_at: event.created_at }
        const entry = this.inbound.get(event.session_id)
        if (!entry) return { ...base, state: "missing" }
        if (entry.room !== room) return { ...base, state: "invalid" }
        let plain
        try {
            const result = entry.session.decrypt(event.ciphertext)
            plain = JSON.parse(result.plaintext)
            result.free()
        } catch (error) {
            return { ...base, state: String(error?.message ?? error).includes("unknown message index") ? "missing" : "invalid" }
        }
        if (plain?.t !== MESSAGE || plain.v !== PROTOCOL || plain.room !== room || typeof plain.body !== "string") {
            return { ...base, state: "invalid" }
        }
        const verified = entry.sender.account === event.sender && entry.sender.device === event.device
            && plain.from?.account === event.sender && plain.from?.device === event.device
        return {
            ...base, state: verified ? "ok" : "unverified", body: plain.body,
            ts: Number.isFinite(plain.ts) ? plain.ts : null, card: card(plain.card)
        }
    }

    async decrypt(room, events) {
        const unknown = [...new Set(events.map(event => event.session_id).filter(id => !this.inbound.has(id)))]
        await this.restore(room, unknown)
        let results = events.map(event => this.open(room, event))
        const retry = [...new Set(events.filter((event, index) => results[index].state === "missing"
            && this.inbound.has(event.session_id)).map(event => event.session_id))]
        if (retry.length) {
            await this.restore(room, retry)
            results = events.map(event => this.open(room, event))
        }
        return results
    }

    async forget() {
        await this.ctx.http.del(`${OLM}/devices/${encodeURIComponent(this.device)}`).catch(() => null)
        await this.ctx.store.del(ChatCrypto.storeKey(this.ctx.user)).catch(() => null)
    }
}
