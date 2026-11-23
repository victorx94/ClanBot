// @ts-nocheck
// Função TEMPORÁRIA para baixar pelo celular o arquivo de contas de um usuário
// a partir do backup cifrado (o mesmo que a função account-backup grava).
// Uso (Safari):  https://<projeto>.supabase.co/functions/v1/export-backup?owner=<uuid>&token=<EXPORT_TOKEN>
// Precisa do secret EXPORT_TOKEN (32+ caracteres). Apague a função depois de usar.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

function fail(status: number, message: string) {
  return new Response(message, { status, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
}

function b64ToBytes(value: string) {
  const bin = atob(value);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

Deno.serve(async (req: Request) => {
  if (req.method !== "GET") return fail(405, "Use GET.");
  const params = new URL(req.url).searchParams;

  const token = Deno.env.get("EXPORT_TOKEN") || "";
  if (token.length < 32) return fail(500, "Crie o secret EXPORT_TOKEN com 32+ caracteres.");
  if (!safeEqual(params.get("token") || "", token)) return fail(403, "Token invalido.");

  const owner = (params.get("owner") || "").trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(owner)) return fail(400, "owner invalido.");
  const which = params.get("file") === "meta" ? "meta" : "accounts";

  const secret = Deno.env.get("ACCOUNT_BACKUP_MASTER_KEY") || "";
  const client = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });

  const { data: head } = await client.from("account_file_backup_heads")
    .select("current_version_id").eq("owner_id", owner).maybeSingle();
  if (!head?.current_version_id) return fail(404, "Nenhum backup para esse usuario.");
  const { data: row } = await client.from("account_file_backup_versions")
    .select("id, encrypted_payload, sha256, accounts_count").eq("owner_id", owner).eq("id", head.current_version_id).maybeSingle();
  if (!row) return fail(404, "Backup nao encontrado.");

  let bundle;
  try {
    // Mesma cifra da account-backup: AES-GCM, chave = SHA-256(master), AAD = owner|versao|account-file-backup-v1
    const env = JSON.parse(row.encrypted_payload);
    const key = await crypto.subtle.importKey("raw",
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret)), "AES-GCM", false, ["decrypt"]);
    const clear = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBytes(env.iv), additionalData: new TextEncoder().encode(`${owner}|${row.id}|account-file-backup-v1`) },
      key, b64ToBytes(env.data));
    bundle = JSON.parse(new TextDecoder().decode(clear));
  } catch {
    return fail(500, "Nao consegui abrir o backup.");
  }

  const b64 = which === "meta" ? bundle.meta_b64 : bundle.accounts_b64;
  if (!b64) return fail(404, "Esse backup nao tem esse arquivo.");

  await client.from("account_file_backup_audit").insert({
    owner_id: owner, actor_id: null, version_id: row.id, action: "admin_download", metadata: { via: "export-backup", file: which },
  });

  const name = which === "meta" ? `meta-${owner.slice(0, 8)}.json` : `contas-${owner.slice(0, 8)}.txt`;
  return new Response(b64ToBytes(b64), {
    headers: {
      "Content-Type": which === "meta" ? "application/json" : "text/plain; charset=utf-8",
      "Content-Disposition": `attachment; filename="${name}"`,
      "Cache-Control": "no-store",
    },
  });
});
