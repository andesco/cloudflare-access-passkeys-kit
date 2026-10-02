import personal from "../cloudflare.local";

const id = personal.database?.id;
if (!id) throw new Error("cloudflare.local.ts must set database.id");
console.log(id);
