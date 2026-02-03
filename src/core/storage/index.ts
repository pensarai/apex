import os from "os";
import path from "path";
import fs from "fs/promises";

import z from "zod";
import { NamedError } from "../../util/errors";
import { Lock } from "../../util/lock";
import { mkdir } from "fs/promises";

export namespace Storage {

    export const NotFoundError = NamedError.create(
        "NotFoundError",
        z.object({
            message: z.string()
        })
    );

    export async function remove(key: string[]) {
        const dir = path.join(os.homedir(), ".pensar");
        const target = path.join(dir, ...key) + ".json";
        return withErrorHandling(async () => {
            await fs.unlink(target).catch(() => {});
        });
    }

    export async function locate(key: string[], ext?: string) {
        const dir = path.join(os.homedir(), ".pensar");
        const target = path.join(dir, ...key) + (ext ? ext : ".json");
        return target;
    }

    export async function write<T>(key: string[], content: T, ext?: string) {
        const dir = path.join(os.homedir(), ".pensar");
        const target = path.join(dir, ...key) + (ext ? ext : ".json");
        return withErrorHandling(async () => {
            using _ = await Lock.write(target);
            await Bun.write(target, JSON.stringify(content, null, 2));
        });
    }

    export async function createDir(key: string[]) {
        const dir = path.join(os.homedir(), ".pensar");
        const target = path.join(dir, ...key);
        return withErrorHandling(async () => {
            using _ = await Lock.write(target);
            await mkdir(target, { recursive: true });
        });
    }

    /**
     * Write raw content (non-JSON) to a file within the .pensar directory
     * @param key Path segments relative to .pensar
     * @param content Raw string content to write
     */
    export async function writeRaw(key: string[], content: string) {
        const dir = path.join(os.homedir(), ".pensar");
        const target = path.join(dir, ...key);
        return withErrorHandling(async () => {
            using _ = await Lock.write(target);
            // Ensure parent directory exists
            const parentDir = path.dirname(target);
            await mkdir(parentDir, { recursive: true });
            await Bun.write(target, content);
        });
    }

    /**
     * Append raw content to a file within the .pensar directory
     * @param key Path segments relative to .pensar
     * @param content Raw string content to append
     */
    export async function appendRaw(key: string[], content: string) {
        const dir = path.join(os.homedir(), ".pensar");
        const target = path.join(dir, ...key);
        return withErrorHandling(async () => {
            using _ = await Lock.write(target);
            // Ensure parent directory exists
            const parentDir = path.dirname(target);
            await mkdir(parentDir, { recursive: true });
            await fs.appendFile(target, content);
        });
    }

    export async function read<T>(key: string[], ext?: string) {
        const dir = path.join(os.homedir(), ".pensar");
        const target = path.join(dir, ...key) + (ext ? ext : ".json");
        return withErrorHandling(async () => {
            using _ = await Lock.read(target);
            const result = ext ?
                await Bun.file(target).text()
                : await Bun.file(target).json();
            return result as T;
        });
    }

    export async function update<T>(key: string[], fn: (draft: T) => void, ext?: string) {
        const dir = path.join(os.homedir(), ".pensar");
        const target = path.join(dir, ...key) + (ext ? ext : ".json");
        return withErrorHandling(async () => {
            using _ = await Lock.write(target);
            const content = ext ?
                await Bun.file(target).text()
                : await Bun.file(target).json();
            fn(content);
            await Bun.write(target, JSON.stringify(content, null, 2));
            return content as T;
        });
    }
    
    async function withErrorHandling<T>(body: () => Promise<T>) {
        return body().catch((e) => {
            if(!(e instanceof Error)) throw e;
            const errnoExcpetion = e as NodeJS.ErrnoException;
            if(errnoExcpetion.code === "ENOENT") {
                throw new NotFoundError({ message: `Resource not found: ${errnoExcpetion.path}`});
            }
            throw e;
        });
    }

    const glob = new Bun.Glob("**/*");
    export async function list(prefix: string[]) {
        const dir = path.join(os.homedir(), ".pensar");
        try {
            const result = await Array.fromAsync(
                glob.scan({
                    cwd: path.join(dir, ...prefix),
                    onlyFiles: true
                })
            ).then((results) => results.map((x) => [...prefix, ...x.slice(0, -5).split(path.sep)]))
            result.sort();
            return result
        } catch {
            return [];
        }
    }


}