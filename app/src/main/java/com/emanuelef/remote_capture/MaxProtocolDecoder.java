/*
 * This file is part of PCAPdroid.
 *
 * PCAPdroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PCAPdroid is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PCAPdroid.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2026 - Emanuele Faranda
 */

package com.emanuelef.remote_capture;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.value.Value;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

/**
 * Decodes MAX messenger protocol frames carried over raw TCP.
 *
 * Frame layout: 10-byte big-endian header (ver u8, cmd u8, seq u16, opcode u16,
 * packed_len u32) followed by {@code packed_len & 0x00FFFFFF} payload bytes.
 * The payload is either msgpack or an LZ4-block-compressed msgpack blob. Nested
 * binary values are probed for the same LZ4+msgpack pattern and expanded.
 *
 * A chunk may contain several concatenated frames; all of them are decoded into
 * one pretty-printed JSON document.
 */
public class MaxProtocolDecoder {
    private static final String TAG = "MaxProtocolDecoder";
    private static final int HEADER_SIZE = 10;
    private static final int KNOWN_VERSION = 0x0a;
    private static final int MAX_PAYLOAD_SIZE = 4 * 1024 * 1024;
    private static final int MAX_DECOMPRESSED_SIZE = 8 * 1024 * 1024;

    private static final Gson prettyGson = new GsonBuilder().setPrettyPrinting().create();

    public static String tryDecode(byte[] data) {
        if ((data == null) || (data.length < HEADER_SIZE))
            return null;
        if ((data[0] & 0xff) != KNOWN_VERSION)
            return null;

        JsonArray frames = new JsonArray();
        int offset = 0;
        while (offset + HEADER_SIZE <= data.length) {
            if ((data[offset] & 0xff) != KNOWN_VERSION)
                break;

            int ver = data[offset] & 0xff;
            int cmd = data[offset + 1] & 0xff;
            int seq = ((data[offset + 2] & 0xff) << 8) | (data[offset + 3] & 0xff);
            int opcode = ((data[offset + 4] & 0xff) << 8) | (data[offset + 5] & 0xff);
            int packedLen = ((data[offset + 6] & 0xff) << 24)
                    | ((data[offset + 7] & 0xff) << 16)
                    | ((data[offset + 8] & 0xff) << 8)
                    | (data[offset + 9] & 0xff);
            int flags = (packedLen >>> 24) & 0xff;
            int payloadLen = packedLen & 0x00FFFFFF;

            if (payloadLen > MAX_PAYLOAD_SIZE)
                return null;
            if (offset + HEADER_SIZE + payloadLen > data.length)
                break;

            byte[] payloadRaw = Arrays.copyOfRange(data, offset + HEADER_SIZE, offset + HEADER_SIZE + payloadLen);
            JsonElement decoded = decodePayload(payloadRaw);

            JsonObject frame = new JsonObject();
            JsonObject header = new JsonObject();
            header.addProperty("ver", ver);
            header.addProperty("cmd", cmd);
            header.addProperty("seq", seq);
            header.addProperty("opcode", opcode);
            header.addProperty("flags", flags);
            header.addProperty("payload_len", payloadLen);
            frame.add("header", header);
            if (decoded != null)
                frame.add("payload", decoded);
            else if (payloadLen > 0)
                frame.addProperty("payload_hex", bytesToHex(payloadRaw));
            frames.add(frame);

            offset += HEADER_SIZE + payloadLen;
        }

        if (frames.size() == 0)
            return null;

        JsonElement out = (frames.size() == 1) ? frames.get(0) : frames;
        return prettyGson.toJson(out);
    }

    private static JsonElement decodePayload(byte[] payload) {
        if (payload.length == 0)
            return new JsonObject();

        try {
            return unpackMsgpack(payload);
        } catch (Exception ignored) {
        }

        try {
            byte[] decompressed = lz4DecompressBlock(payload);
            return unpackMsgpack(decompressed);
        } catch (Exception e) {
            Log.d(TAG, "LZ4+msgpack failed: " + e);
        }
        return null;
    }

    private static JsonElement unpackMsgpack(byte[] data) throws IOException {
        try (MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(data)) {
            Value v = unpacker.unpackValue();
            if (unpacker.hasNext())
                throw new IOException("trailing bytes after msgpack value");
            return valueToJson(v);
        }
    }

    private static JsonElement valueToJson(Value v) {
        if (v == null || v.isNilValue())
            return JsonNull.INSTANCE;
        if (v.isBooleanValue())
            return new JsonPrimitive(v.asBooleanValue().getBoolean());
        if (v.isIntegerValue())
            return new JsonPrimitive(v.asIntegerValue().toLong());
        if (v.isFloatValue())
            return new JsonPrimitive(v.asFloatValue().toDouble());
        if (v.isStringValue())
            return new JsonPrimitive(v.asStringValue().asString());
        if (v.isBinaryValue()) {
            byte[] bytes = v.asBinaryValue().asByteArray();
            JsonElement nested = tryDecodeNestedBlob(bytes);
            if (nested != null)
                return nested;
            return new JsonPrimitive(bytesToHex(bytes));
        }
        if (v.isArrayValue()) {
            JsonArray arr = new JsonArray();
            for (Value item : v.asArrayValue())
                arr.add(valueToJson(item));
            return arr;
        }
        if (v.isMapValue()) {
            JsonObject obj = new JsonObject();
            for (Map.Entry<Value, Value> e : v.asMapValue().entrySet()) {
                String key = mapKey(e.getKey());
                obj.add(key, valueToJson(e.getValue()));
            }
            return obj;
        }
        if (v.isExtensionValue())
            return new JsonPrimitive("ext(" + v.asExtensionValue().getType() + "):" + bytesToHex(v.asExtensionValue().getData()));
        return new JsonPrimitive(v.toJson());
    }

    private static String mapKey(Value v) {
        if (v.isStringValue())
            return v.asStringValue().asString();
        if (v.isIntegerValue())
            return Long.toString(v.asIntegerValue().toLong());
        return v.toJson();
    }

    private static JsonElement tryDecodeNestedBlob(byte[] bytes) {
        if (bytes.length < 2)
            return null;
        try {
            byte[] decompressed = lz4DecompressBlock(bytes);
            return unpackMsgpack(decompressed);
        } catch (Exception ignored) {
        }
        try {
            return unpackMsgpack(bytes);
        } catch (Exception ignored) {
        }
        return null;
    }

    // LZ4 block decoder — ported from the reference Python implementation.
    static byte[] lz4DecompressBlock(byte[] src) throws IOException {
        GrowableBytes dst = new GrowableBytes(Math.min(src.length * 4, 64 * 1024));
        int pos = 0;

        while (pos < src.length) {
            int token = src[pos++] & 0xff;

            int litLen = token >>> 4;
            if (litLen == 15) {
                while (pos < src.length) {
                    int b = src[pos++] & 0xff;
                    litLen += b;
                    if (b != 255) break;
                }
            }
            if (litLen > 0) {
                if (pos + litLen > src.length)
                    throw new IOException("LZ4: literal out of bounds");
                dst.write(src, pos, litLen);
                pos += litLen;
                if (dst.size > MAX_DECOMPRESSED_SIZE)
                    throw new IOException("LZ4: output too large");
            }

            if (pos >= src.length)
                break;
            if (pos + 1 >= src.length)
                throw new IOException("LZ4: incomplete offset");

            int offset = (src[pos] & 0xff) | ((src[pos + 1] & 0xff) << 8);
            pos += 2;
            if (offset == 0)
                throw new IOException("LZ4: zero offset");

            int matchLen = (token & 0x0f) + 4;
            if ((token & 0x0f) == 0x0f) {
                while (pos < src.length) {
                    int b = src[pos++] & 0xff;
                    matchLen += b;
                    if (b != 255) break;
                }
            }

            int matchPos = dst.size - offset;
            if (matchPos < 0)
                throw new IOException("LZ4: match out of bounds");
            for (int i = 0; i < matchLen; i++)
                dst.writeByte(dst.buf[matchPos + (i % offset)]);
            if (dst.size > MAX_DECOMPRESSED_SIZE)
                throw new IOException("LZ4: output too large");
        }

        return dst.toArray();
    }

    private static String bytesToHex(byte[] data) {
        int shown = Math.min(data.length, 128);
        StringBuilder sb = new StringBuilder(shown * 2 + 16);
        for (int i = 0; i < shown; i++)
            sb.append(String.format("%02x", data[i]));
        if (data.length > shown)
            sb.append("... (").append(data.length).append(" bytes)");
        return sb.toString();
    }

    private static final class GrowableBytes {
        byte[] buf;
        int size;

        GrowableBytes(int cap) {
            buf = new byte[Math.max(cap, 16)];
        }

        private void ensure(int additional) {
            if (size + additional <= buf.length) return;
            int newCap = Math.max(buf.length * 2, size + additional);
            buf = Arrays.copyOf(buf, newCap);
        }

        void writeByte(byte b) {
            ensure(1);
            buf[size++] = b;
        }

        void write(byte[] src, int off, int len) {
            ensure(len);
            System.arraycopy(src, off, buf, size, len);
            size += len;
        }

        byte[] toArray() {
            return Arrays.copyOf(buf, size);
        }
    }
}
