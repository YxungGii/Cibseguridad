/* =====================================================================
   LAB SQL INJECTION — app.js
   Edita SUPABASE_URL y SUPABASE_ANON_KEY con los datos de tu proyecto.
   ===================================================================== */

const SUPABASE_URL = "https://TU-PROYECTO.supabase.co";
const SUPABASE_ANON_KEY = "TU_ANON_KEY";

const LabApp = (function () {

  // ---------------------------------------------------------------
  // Estado del modo. true = usa funciones seguras (parametrizadas)
  //                  false = usa funciones vulnerables (por defecto)
  // Se puede cambiar en caliente desde la consola del navegador:
  //   LabApp.setSafeMode(true)
  //   LabApp.setSafeMode(false)
  //   LabApp.status()
  // ---------------------------------------------------------------
  let safeMode = false;

  function setSafeMode(value) {
    safeMode = !!value;
    updateStatusUI();
    console.log(`[LabApp] modo seguro: ${safeMode}`);
  }

  function status() {
    console.log(`[LabApp] modo actual: ${safeMode ? "SEGURO" : "VULNERABLE"}`);
    return safeMode;
  }

  function updateStatusUI() {
    const el = document.getElementById("mode-status");
    if (!el) return;
    el.innerHTML = safeMode
      ? '<span class="msg ok">Modo SEGURO — funciones parametrizadas</span>'
      : '<span class="msg err">Modo VULNERABLE — funciones concatenadas (por defecto)</span>';
  }

  // ---------------------------------------------------------------
  // Llamada genérica a una función RPC de Supabase
  // ---------------------------------------------------------------
  async function callRpc(fnName, body) {
    const resp = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fnName}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
      },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.message || "Error en la consulta");
    return data;
  }

  function renderTable(rows) {
    if (!rows || rows.length === 0) return '<div class="msg err">Sin resultados.</div>';
    const cols = Object.keys(rows[0]);
    let html = "<table><thead><tr>" + cols.map((c) => `<th>${c}</th>`).join("") + "</tr></thead><tbody>";
    rows.forEach((r) => {
      html += "<tr>" + cols.map((c) => `<td>${r[c] ?? ""}</td>`).join("") + "</tr>";
    });
    html += "</tbody></table>";
    return html;
  }

  // =================================================================
  // LOGIN
  // Función vulnerable: login_vulnerable  -> concatena el input
  // Función segura:     login_seguro      -> usa parámetros
  // Para DESHABILITAR el endpoint vulnerable directamente en Supabase,
  // ver setup.sql (sección "DESHABILITAR DESDE CONSOLA SQL").
  // =================================================================
  async function login() {
    const user = document.getElementById("login-user").value;
    const pass = document.getElementById("login-pass").value;
    const out = document.getElementById("login-result");
    out.innerHTML = "Consultando...";
    const fn = safeMode ? "login_seguro" : "login_vulnerable";
    const preview = safeMode
      ? `select * from usuarios where usuario = $1 and clave = $2\n-- parámetros: [${JSON.stringify(user)}, ${JSON.stringify(pass)}]`
      : `select * from usuarios where usuario='${user}' and clave='${pass}'`;
    try {
      const rows = await callRpc(fn, { p_usuario: user, p_clave: pass });
      out.innerHTML =
        (rows.length > 0
          ? '<div class="msg ok">✅ Acceso concedido</div>' + renderTable(rows)
          : '<div class="msg err">❌ Usuario o contraseña incorrectos</div>') +
        `<div class="query-preview">${preview}</div>`;
    } catch (e) {
      out.innerHTML = `<div class="msg err">Error: ${e.message}</div><div class="query-preview">${preview}</div>`;
    }
  }

  // =================================================================
  // BUSCADOR
  // Función vulnerable: buscar_producto_vulnerable -> concatena el input
  // Función segura:     buscar_producto_seguro      -> usa parámetros
  // =================================================================
  async function search() {
    const term = document.getElementById("search-term").value;
    const out = document.getElementById("search-result");
    out.innerHTML = "Buscando...";
    const fn = safeMode ? "buscar_producto_seguro" : "buscar_producto_vulnerable";
    const preview = safeMode
      ? `select * from productos where nombre ilike '%' || $1 || '%'\n-- parámetro: [${JSON.stringify(term)}]`
      : `select * from productos where nombre ilike '%${term}%'`;
    try {
      const rows = await callRpc(fn, { p_termino: term });
      out.innerHTML = renderTable(rows) + `<div class="query-preview">${preview}</div>`;
    } catch (e) {
      out.innerHTML = `<div class="msg err">Error: ${e.message}</div><div class="query-preview">${preview}</div>`;
    }
  }

  document.addEventListener("DOMContentLoaded", updateStatusUI);

  // API pública expuesta a window para poder invocarla desde la consola
  return { login, search, setSafeMode, status };
})();

// Queda disponible como variable global: LabApp.setSafeMode(true/false)
window.LabApp = LabApp;
