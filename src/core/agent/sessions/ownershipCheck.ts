import path from "path";
import fs from "fs/promises";
import { CONFIG_DIR_PATH } from "../../config/config";
import { nanoid } from "nanoid";
import { getDnsRecords, type DnsRecord } from "@layered/dns-records";

const DNS_RECORD_KEYS_PATH = path.join(CONFIG_DIR_PATH, "keys"); // txt file containing records of all generated TXT DNS record values and associated domains

const isTargetRemote = (target: string) => {
 const url = new URL(target);
 return !(url.hostname === "localhost" || url.hostname === "127.0.0.1");
};

const findTxtRecordForDomain = async (domain: string) => {
    const keysExists = await fs
        .access(DNS_RECORD_KEYS_PATH)
        .then(() => true)
        .catch(() => false);
    if(!keysExists) throw new Error("Local dns record mapping file does not exist.");

    const records = (await fs.readFile(DNS_RECORD_KEYS_PATH, 'utf-8')).split("\n");
    if(records.length === 0) {
        throw new Error("Records file is empty");
    }
    for(let i=0;i<records.length;i++) {
        let [key, value] = records[i]!.split(";");
        if(key === domain) {
            return { domain: key, value }
        }
    }
    return null;
}

const checkTxtRecordExistsLocally = async (domain: string) => {
    const keysExists = await fs
        .access(DNS_RECORD_KEYS_PATH)
        .then(() => true)
        .catch(() => false);
    if(!keysExists) throw new Error("Local dns record mapping file does not exist.");

    const records = (await fs.readFile(DNS_RECORD_KEYS_PATH, 'utf-8')).split("\n");
    if(records.length === 0) {
        return false;
    }
    for(let i=0;i<records.length;i++) {
        let [key, value] = records[i]!.split(";");
        if(key === domain) {
            return true;
        }
    }
    return false;
}

const generateTxtRecordContent = async (domain: string) => {
   const keysExists = await fs
    .access(DNS_RECORD_KEYS_PATH)
    .then(() => true)
    .catch(() => false);

    if(!keysExists) {
        await fs.writeFile(DNS_RECORD_KEYS_PATH, "");
    }

    const recordValue = `pensar_${nanoid()}${nanoid(4)}`;

    await fs.appendFile(DNS_RECORD_KEYS_PATH,`${domain};${recordValue}\n`);

    return { domain, value: recordValue};
}

async function runDnsOwnershipCheck(target: string) {
    if(!isTargetRemote(target)) {
        return true;
    }

    const _url = new URL(target);

    const domain = _url.hostname;

    const record = await findTxtRecordForDomain(domain);

    if(!record) {
        throw new Error("Record not found.");
    }

    let txtRecords: DnsRecord[];
    try {
        txtRecords = await getDnsRecords(domain.replace("www.",""), 'TXT');
    } catch(error) {
        throw new Error(`Error with dns lookup/resolver: ${error}`);
    }

    for(const txtRecord of txtRecords) {
        if(txtRecord.data === record.value) return true;
    }

    return false;
}

// TODO: create tui ux/flow for this

export {
    generateTxtRecordContent,
    runDnsOwnershipCheck
};