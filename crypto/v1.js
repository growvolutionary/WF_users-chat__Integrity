/********************************************************************
 *                                                                  *
 *    Copyright © 2026 GrowVolution Media, Inh. Pierre Schkoldow    *
 *                                                                  *
 *      This script encrypts the conversations of the WebFluid      *
 *        "users-chat" Additive on your device. To keep your        *
 *     application transparent and secure, you should not edit      *
 *    or change its content by yourself. Additionally we highly     *
 *         recommend to add the "peering" Additive to your          *
 *    application and to not remove the "users-chat" Additive's     *
 *                        peering features.                         *
 *                                                                  *
 ********************************************************************/

import * as vodozemac from "../../../users/static/vendor/vodozemac/0.1.0/vodozemac_bg.js"

const subtle = globalThis.crypto.subtle

export const PROTOCOL = 1
export const WASM_SHA256 = "5b3a606864bbcfe31f4e91f12e73b659c494f6d13c36cb6e1ec94dce992410fd"

const PREFIX = new URL(import.meta.url).pathname.replace(/\/static\/js\/chat\.js$/, "")
export const ROOM_KEY = "users-chat/room-key"
const MESSAGE = "users-chat/message"
const ROTATE_MESSAGES = 100
const ROTATE_AGE = 7 * 24 * 3600 * 1000
const NAME_LENGTH = 64
const LOADED = Symbol.for("wf.users.vodozemac")
const QUOTE_LENGTH = 160
const FILE_NAME_LENGTH = 255
const THUMB_LENGTH = 16384
const MEDIA_ID = /^[A-Za-z0-9_-]{22}$/
const REFERENCE_LENGTH = 512
const LEGACY_DATABASE = "users-chat"
const LEGACY_STORE = "state"



export class ChatError extends Error {
    constructor(code) {
        super(code)
        this.code = code
    }
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

function name(value) {
    return typeof value === "string" && value.trim() ? value.trim().slice(0, NAME_LENGTH) : null
}

export function card(value) {
    const first = name(value?.first)
    return first ? { first, last: name(value?.last) } : null
}

export function quote(value) {
    if (!Number.isInteger(value?.seq) || value.seq < 1 || typeof value.sender !== "string" || !value.sender) return null
    const text = typeof value.text === "string" ? value.text.trim().slice(0, QUOTE_LENGTH) : ""
    return { seq: value.seq, sender: value.sender, text }
}

export function attachment(value) {
    if (value?.v !== 1 || value.alg !== "A256GCM" || typeof value.id !== "string" || !MEDIA_ID.test(value.id)
        || typeof value.key !== "string" || typeof value.iv !== "string" || !Number.isInteger(value.size)
        || value.size < 0) return null
    const file = {
        v: 1, alg: "A256GCM", id: value.id, key: value.key, iv: value.iv, size: value.size,
        mime: typeof value.mime === "string" && value.mime && value.mime.length <= 128 ? value.mime : "application/octet-stream",
        name: typeof value.name === "string" && value.name.trim() ? value.name.trim().slice(0, FILE_NAME_LENGTH) : null
    }
    if (Number.isInteger(value.w) && value.w > 0) file.w = value.w
    if (Number.isInteger(value.h) && value.h > 0) file.h = value.h
    if (typeof value.thumb === "string" && value.thumb.startsWith("data:image/") && value.thumb.length <= THUMB_LENGTH) {
        file.thumb = value.thumb
    }
    return file
}

export function uploadReference(value) {
    if (value?.v !== 1 || typeof value.url !== "string" || !value.url || value.url.length > REFERENCE_LENGTH) return null
    let url
    try { url = new URL(value.url) } catch { return null }
    if (url.protocol !== "https:" && url.protocol !== "http:") return null
    const upload = {
        v: 1, url: url.href,
        mime: typeof value.mime === "string" && value.mime && value.mime.length <= 128 ? value.mime : "application/octet-stream",
        name: typeof value.name === "string" && value.name.trim() ? value.name.trim().slice(0, FILE_NAME_LENGTH) : null
    }
    if (Number.isInteger(value.size) && value.size >= 0) upload.size = value.size
    if (Number.isInteger(value.w) && value.w > 0) upload.w = value.w
    if (Number.isInteger(value.h) && value.h > 0) upload.h = value.h
    return upload
}

export function load(wasm) {
    globalThis[LOADED] ??= (async () => {
        const bytes = wasm ?? await fetch(new URL("../../../users/static/vendor/vodozemac/0.1.0/vodozemac_bg.wasm",
            import.meta.url), { credentials: "same-origin" }).then(response => {
            if (!response.ok) throw new ChatError("CRYPTO_UNAVAILABLE")
            return response.arrayBuffer()
        })
        if (await hex(bytes) !== WASM_SHA256) throw new ChatError("CRYPTO_MISMATCH")
        const { instance } = await WebAssembly.instantiate(bytes, { "./vodozemac_bg.js": vodozemac })
        vodozemac.__wbg_set_wasm(instance.exports)
        instance.exports.__wbindgen_start()
        return vodozemac
    })().catch(error => {
        delete globalThis[LOADED]
        throw error
    })
    return globalThis[LOADED]
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

export async function legacyDevice(user, store = idbStore(LEGACY_DATABASE, LEGACY_STORE)) {
    const key = `device:${user}`
    const record = await store.get(key).catch(() => null)
    return { record: record?.v === PROTOCOL ? record : null, drop: () => store.del(key).catch(() => null) }
}

function transient(error) {
    return !error?.status || error.status >= 500 || error.status === 429
}

export class ChatCrypto {
    constructor(ctx) {
        this.ctx = ctx
        this.vz = ctx.vz
        this.prefix = ctx.prefix ?? PREFIX
        this.users = ctx.device
        this.outbound = new Map()
        this.inbound = new Map()
        this.accepted = 0
        this.queue = Promise.resolve()
        this.unregister = null
    }

    static open(ctx) {
        if (!ctx.device || ctx.device.ctx.account !== ctx.account) throw new ChatError("DEVICE_MISMATCH")
        const crypto = new ChatCrypto(ctx)
        const register = ctx.register ?? ((type, handler) => ctx.device.register(type, handler))
        crypto.unregister = register(ROOM_KEY, message => crypto.roomKey(message))
        return crypto
    }

    get device() {
        return this.users.device
    }

    get identity() {
        return this.users.identity
    }

    get olm() {
        return this.users.olm
    }

    serial(work) {
        const run = this.queue.then(work, work)
        this.queue = run.catch(() => null)
        return run
    }

    self() {
        return this.users.self()
    }

    publish() {
        return this.users.publish()
    }

    devices(account, fresh = false) {
        return this.users.devices(account, fresh)
    }

    notice(account) {
        return this.users.notice(account)
    }

    acknowledge(account) {
        return this.users.acknowledge(account)
    }

    address(record) {
        return `${record.account}/${record.device}`
    }

    async share(room, out) {
        for (const account of room.members) {
            const devices = await this.users.devices(account)
            if (account !== this.ctx.account && !devices.length) throw new ChatError("NO_DEVICES")
            for (const record of devices.filter(item => !out.shared.has(this.address(item)))) {
                const payload = {
                    t: ROOM_KEY, v: PROTOCOL, room: room.id, session_id: out.session.session_id,
                    session_key: out.session.session_key, sender: this.self(),
                    recipient: { account: record.account, device: record.device }
                }
                try {
                    await this.users.sendTo(record, JSON.stringify(payload))
                    out.shared.add(this.address(record))
                } catch (error) {
                    if (error?.code !== "NO_ONE_TIME_KEY" && error?.code !== "UNTRUSTED_BINDING" && error?.status !== 404) throw error
                }
            }
        }
    }

    encrypt(room, body, sender, extra = {}) {
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
                await this.backup(room.id, session.session_id, entry).catch(() => null)
            }
            await this.share(room, out)
            const plain = {
                t: MESSAGE, v: PROTOCOL, room: room.id, body, ts: Number.isFinite(extra.ts) ? extra.ts : Date.now(),
                from: { account: this.ctx.account, device: this.device }, card: card(sender)
            }
            const reply = quote(extra.reply)
            if (reply) plain.reply = reply
            if (Number.isInteger(extra.edit) && extra.edit > 0) plain.edit = extra.edit
            const file = attachment(extra.file)
            if (file) plain.file = file
            const upload = uploadReference(extra.upload)
            if (upload && !file) plain.upload = upload
            const ciphertext = out.session.encrypt(JSON.stringify(plain))
            out.count += 1
            return { device: this.device, session_id: out.session.session_id, ciphertext }
        })
    }

    roomKey(message) {
        return this.serial(async () => {
            const data = message?.data
            if (data?.t !== ROOM_KEY || data.v !== PROTOCOL) return false
            if (data.recipient?.account !== message.recipient?.account || data.recipient?.device !== message.recipient?.device
                || data.recipient?.account !== this.ctx.account) return false
            const from = data.sender ?? {}
            const sender = message.sender ?? {}
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
            const entry = { session, room: data.room, sender: { account: from.account, device: from.device, ed25519: from.ed25519 } }
            try {
                await this.backup(data.room, data.session_id, entry)
            } catch (error) {
                if (transient(error)) {
                    session.free()
                    throw error
                }
            }
            existing?.session.free()
            this.inbound.set(data.session_id, entry)
            this.accepted += 1
            return true
        })
    }

    async receive() {
        const before = this.accepted
        await this.users.receive()
        return this.accepted - before
    }

    async backup(room, sessionId, entry) {
        const index = entry.session.first_known_index
        const key = entry.session.export_at(index)
        if (!key) return
        const data = await this.ctx.sealer.encrypt(JSON.stringify({
            v: PROTOCOL, room, session_id: sessionId, key, first_index: index, sender: entry.sender
        }))
        await this.ctx.http.put(`${this.prefix}/api/v1/keys`, { keys: [{ room, session_id: sessionId, first_index: index, data }] })
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

    knows(sessionId) {
        return this.inbound.has(sessionId)
    }

    open(room, event) {
        const base = {
            seq: event.seq, rev: event.rev ?? 0, sender: event.sender ?? null, created_at: event.created_at ?? null,
            edited_at: event.edited_at ?? null, expires_at: event.expires_at ?? null
        }
        if (event.hidden) return { ...base, state: "hidden" }
        if (event.kind === "notice") return { ...base, state: "notice", notice: event.notice ?? null }
        if (event.deleted) return { ...base, state: "deleted" }
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
        if (plain?.t !== MESSAGE || plain.v !== PROTOCOL || plain.room !== room || typeof plain.body !== "string"
            || ("edit" in plain && plain.edit !== event.seq)) {
            return { ...base, state: "invalid" }
        }
        const file = event.kind === "attachment" ? attachment(plain.file) : null
        if (event.kind === "attachment" && file?.id !== event.media) return { ...base, state: "invalid" }
        const verified = entry.sender.account === event.sender && entry.sender.device === event.device
            && plain.from?.account === event.sender && plain.from?.device === event.device
        return {
            ...base, state: verified ? "ok" : "unverified", body: plain.body,
            ts: Number.isFinite(plain.ts) ? plain.ts : null, card: card(plain.card), reply: quote(plain.reply),
            file, upload: event.kind === "message" ? uploadReference(plain.upload) : null
        }
    }

    async decrypt(room, events) {
        const sealed = events.filter(event => !event.hidden && !event.deleted && event.kind !== "notice")
        const unknown = [...new Set(sealed.map(event => event.session_id).filter(id => id && !this.inbound.has(id)))]
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

    close() {
        this.unregister?.()
        this.unregister = null
    }

    async forget() {
        this.close()
        await this.users.forget()
    }
}
