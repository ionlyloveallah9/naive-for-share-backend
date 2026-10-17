import { createClient } from "@supabase/supabase-js";

export default async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({
      ok: false,
      error: "Method not allowed"
    });
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;

  if (!url || !secretKey) {
    return res.status(503).json({
      ok: false,
      error: "Supabase server configuration is missing"
    });
  }

  try {
    const supabase = createClient(url, secretKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false
      }
    });

    const { error } = await supabase
      .from("share_rooms")
      .select("id")
      .limit(1);

    if (error) {
      console.error("Supabase health check failed:", error.code);

      return res.status(503).json({
        ok: false,
        error: "Supabase database check failed",
        code: error.code ?? "UNKNOWN"
      });
    }

    return res.status(200).json({
      ok: true,
      service: "naive-for-share-backend",
      supabaseConnected: true
    });
  } catch (error) {
    console.error("Supabase connection error");

    return res.status(503).json({
      ok: false,
      error: "Unable to connect to Supabase"
    });
  }
}
