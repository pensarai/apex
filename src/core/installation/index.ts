export namespace Installation {
    
    export async function getVersion() {
        if(process.env['APEX_VERSION']) return process.env['APEX_VERSION'];

        const version = await fetch('https://registry.npmjs.org/@pensar/apex/latest')
                        .then(async (res) => {
                            if(!res.ok) throw new Error(res.statusText);
                            let data = await res.json() as any;
                            return data.version;
                        });
                        // .then((data: any) => {console.log(data); return data.version});
        return version;
    }

    
}