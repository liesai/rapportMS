import gradio as gr
import pandas as pd
import tempfile

# ===========================================
#   ABRÉVIATIONS DES CATÉGORIES
# ===========================================

CATEGORY_ABBR = {
    "global": "glb",
    "storage_data": "std",
    "storage_mgmt": "stm",
    "synapse": "syn",
    "sql_rbac": "sqr",
    "sql_db": "sqb",
    "ml": "aml",
    "functions": "fnc"
}

# ===========================================
#   RACCOURCISSEMENT (max 8 chars)
# ===========================================

def shorten(value, max_len=8):
    if not value:
        return ""
    return value.lower().replace(" ", "").replace("-", "").replace("_", "")[:max_len]


# ===========================================
#   ROLES MICROSOFT (catalogue enrichi)
# ===========================================

ROLE_CATALOG = {
    "global": ["Owner", "Contributor", "Reader", "User Access Administrator"],
    "storage_data": [
        "Storage Blob Data Owner",
        "Storage Blob Data Contributor",
        "Storage Blob Data Reader",
        "Storage Blob Delegator"
    ],
    "storage_mgmt": [
        "Storage Account Contributor",
        "Storage Account Key Operator Service Role",
        "Storage Account Backup Contributor"
    ],
    "synapse": [
        "Synapse Administrator",
        "Synapse Apache Spark Administrator",
        "Synapse SQL Administrator",
        "Synapse Contributor",
        "Synapse Artifact Publisher",
        "Synapse Artifact User",
        "Synapse Compute Operator",
        "Synapse Monitoring Operator",
        "Synapse Credential User",
        "Synapse Linked Data Manager",
        "Synapse User"
    ],
    "sql_rbac": [
        "SQL Server Contributor",
        "SQL DB Contributor",
        "SQL Security Manager",
        "SQL Managed Instance Contributor"
    ],
    "sql_db": ["db_datareader", "db_datawriter", "db_ddladmin", "db_owner"],
    "ml": [
        "AzureML Data Scientist",
        "AzureML Compute Operator",
        "AzureML Registry User",
        "AzureML Metrics Writer",
        "Contributor (ML workspace)",
        "Reader (ML workspace)"
    ],
    "functions": [
        "Contributor (Function App)",
        "Reader (Function App)",
        "Website Contributor"
    ],
    "monitoring": [
        "Monitoring Reader", "Log Analytics Reader", "Log Analytics Contributor"
    ],
    "security": [
        "Security Reader", "Security Admin"
    ],
    "network": [
        "Network Contributor", "Private DNS Zone Contributor"
    ],
    "eventhub": [
        "Azure Event Hubs Data Owner",
        "Azure Event Hubs Data Sender",
        "Azure Event Hubs Data Receiver"
    ],
    "keyvault": [
        "Key Vault Reader",
        "Key Vault Secrets Officer",
        "Key Vault Crypto Officer"
    ],
    "datafactory": [
        "Data Factory Contributor",
        "Data Factory Reader"
    ]
}

# ===========================================
#   PERSONAS
# ===========================================

PERSONA_BUNDLES = {
    "platform-ops": {
        "description": "Administrateur plateforme",
        "roles": {
            "global": ["Contributor", "User Access Administrator"],
            "storage_data": ["Storage Blob Data Owner"],
            "storage_mgmt": ["Storage Account Contributor"],
            "synapse": ["Synapse Administrator"],
            "sql_rbac": ["SQL Server Contributor", "SQL Security Manager"],
            "ml": ["AzureML Data Scientist", "AzureML Compute Operator"],
            "functions": ["Contributor (Function App)"],
            "monitoring": ["Log Analytics Reader"],
            "security": ["Security Reader"]
        }
    },
    "data-engineer": {
        "description": "Ingénieur Data",
        "roles": {
            "global": ["Contributor"],
            "storage_data": ["Storage Blob Data Contributor", "Storage Blob Data Reader"],
            "synapse": ["Synapse Contributor", "Synapse Linked Data Manager"],
            "sql_rbac": ["SQL DB Contributor"],
            "sql_db": ["db_datareader", "db_datawriter"],
            "ml": ["AzureML Compute Operator"],
            "monitoring": ["Log Analytics Reader"],
            "network": ["Network Contributor"]
        }
    },
    "data-scientist": {
        "description": "Scientifique de données",
        "roles": {
            "global": ["Reader"],
            "storage_data": ["Storage Blob Data Reader"],
            "synapse": ["Synapse Artifact User"],
            "sql_db": ["db_datareader"],
            "ml": ["AzureML Data Scientist"],
            "monitoring": ["Monitoring Reader"]
        }
    },
    "bi-analyst": {
        "description": "Analyste BI",
        "roles": {
            "global": ["Reader"],
            "storage_data": ["Storage Blob Data Reader"],
            "synapse": ["Synapse Artifact User"],
            "sql_db": ["db_datareader"],
            "monitoring": ["Monitoring Reader"]
        }
    },
    "support-engineer": {
        "description": "Support technique",
        "roles": {
            "global": ["Reader"],
            "storage_data": ["Storage Blob Data Reader"],
            "synapse": ["Synapse Monitoring Operator"],
            "functions": ["Reader (Function App)"],
            "monitoring": ["Monitoring Reader"]
        }
    }
}


# ===========================================
#   RECO MICROSOFT : scope recommandé
# ===========================================

def determine_scope(category, role):
    if category == "global":
        return "subscription"
    if category == "storage_mgmt":
        return "resource-group"
    if category == "storage_data":
        return "storage-account"
    if category == "sql_rbac":
        return "sql-server"
    if category == "sql_db":
        return "database"
    if category == "synapse":
        return "synapse-workspace"
    if category == "ml":
        return "ml-workspace"
    if category == "functions":
        return "function-app"
    if category in ["monitoring", "security"]:
        return "tenant"
    return "resource-group"


# ===========================================
#   RBAC / ACL / DATABASE / ABAC
# ===========================================

def determine_access_model(category, role):
    if category == "storage_data":
        return "ACL (POSIX) + RBAC"
    if category == "sql_db":
        return "Database Role"
    if "Conditional" in role:
        return "ABAC"
    return "RBAC"


# ===========================================
#   CRITICITÉ
# ===========================================

def determine_criticality(role):
    critical = [
        "Owner", "User Access Administrator",
        "Synapse Administrator",
        "SQL Security Manager"
    ]
    high = [
        "Contributor", "Storage Blob Data Owner",
        "SQL DB Contributor", "Synapse Contributor",
        "AzureML Compute Operator"
    ]
    if role in critical:
        return "Critique (PIM requis)"
    if role in high:
        return "Important"
    if "Reader" in role:
        return "Lecture"
    return "Standard"


# ===========================================
#   GENERATION GROUPES
# ===========================================

def generate_group_profile(domain, project, team, persona, env):
    return f"grt-{shorten(domain)}-{shorten(project)}-{shorten(team)}-{shorten(persona)}-{env}"

def generate_group_role(domain, project, team, persona, category, env):
    return f"grr-{shorten(domain)}-{shorten(project)}-{shorten(team)}-{shorten(persona)}-{CATEGORY_ABBR.get(category,category[:3])}-{env}"


# ===========================================
#   GAP ANALYSIS
# ===========================================

def gap_analysis(persona, category, roles):
    missing = []
    if persona == "data-scientist" and "Synapse Artifact User" not in roles:
        missing.append("Synapse Artifact User conseillé pour les DS")
    if persona == "data-engineer" and "Synapse Linked Data Manager" not in roles:
        missing.append("Synapse Linked Data Manager conseillé pour les DE")
    return missing


# ===========================================
#   BEST PRACTICES CHECKS
# ===========================================

def best_practice_checks(df):
    checks = []

    # 1. Trop de permissions par GRT
    bloated = df.groupby("GRT")["Rôle"].count()
    for grt, count in bloated.items():
        if count > 35:
            checks.append(f"⚠️ {grt} contient {count} permissions (role bloat).")

    # 2. PIM requis
    for _, row in df[df["Criticité"].str.contains("Critique")].iterrows():
        checks.append(f"🔒 Rôle critique sans PIM : {row['Rôle']} ({row['Persona']})")

    # 3. Storage Owner
    for _, row in df[df["Rôle"] == "Storage Blob Data Owner"].iterrows():
        checks.append(f"⚠️ Storage Blob Data Owner accordé à {row['Persona']} — très puissant.")

    # 4. Key Vault access
    kv = df[df["Rôle"] == "Key Vault Secrets Officer"]
    for _, row in kv.iterrows():
        checks.append(f"⚠️ Key Vault Secrets Officer très sensible : {row['Persona']}")

    return checks


# ===========================================
#   GENERATION DU TABLEAU (inclut df_grouped)
# ===========================================

def generate_table(domain, project, team, env, personas):
    raw_rows = []
    warnings = []
    gaps = []

    for persona in personas:
        persona_roles = PERSONA_BUNDLES.get(persona, {}).get("roles", {})
        grt = generate_group_profile(domain, project, team, persona, env)

        if len(grt) > 63:
            warnings.append(f"GRT trop long ({len(grt)}): {grt}")

        for cat, roles in persona_roles.items():
            gaps += gap_analysis(persona, cat, roles)

        for category, role_list in persona_roles.items():
            grr = generate_group_role(domain, project, team, persona, category, env)
            if len(grr) > 63:
                warnings.append(f"GRR trop long ({len(grr)}): {grr}")

            for role in role_list:
                raw_rows.append({
                    "Persona": persona,
                    "GRT": grt,
                    "GRR": grr,
                    "Catégorie": category,
                    "Rôle": role,
                    "Scope recommandé": determine_scope(category, role),
                    "Niveau d’accès": determine_access_model(category, role),
                    "Criticité": determine_criticality(role),
                    "Len(GRT)": len(grt),
                    "Len(GRR)": len(grr)
                })

    df_raw = pd.DataFrame(raw_rows)

    # === GROUPBY : regroupe les rôles par catégorie ===
    df_grouped = (
        df_raw.groupby([
            "Persona", "GRT", "GRR", "Catégorie",
            "Scope recommandé", "Niveau d’accès",
            "Criticité", "Len(GRT)", "Len(GRR)"
        ])
        .agg({"Rôle": lambda x: ", ".join(sorted(set(x)))})
        .reset_index()
    )

    return df_grouped, warnings, gaps


# ===========================================
#   EXPORT CSV
# ===========================================

def export_csv(df):
    if df.empty:
        return None
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
    df.to_csv(tmp.name, index=False, sep=";")
    return tmp.name


# ===========================================
#   INTERFACE GRADIO UI
# ===========================================

with gr.Blocks(title="Azure RBAC Generator") as app:

    gr.Markdown("# 🔧 Générateur Azure RBAC – regroupement des rôles & best practices MS")

    with gr.Row():
        domain = gr.Textbox(label="Domaine")
        project = gr.Textbox(label="Projet")
        team = gr.Textbox(label="Équipe")
        env = gr.Dropdown(["dev", "qa", "preprod", "prod"], label="Environnement")

    personas = gr.CheckboxGroup(
        choices=list(PERSONA_BUNDLES.keys()),
        label="Personas"
    )

    generate_btn = gr.Button("📊 Générer")

    df_output = gr.DataFrame(interactive=False, label="Résultat")
    warnings_box = gr.Markdown()
    gaps_box = gr.Markdown()
    bestpractice_box = gr.Markdown()
    csv_file = gr.File(label="Télécharger CSV")

    def run(domain, project, team, env, personas):
        df, warnings, gaps = generate_table(domain, project, team, env, personas)
        bp = best_practice_checks(df)

        warn_text = "✔️ Aucun avertissement." if not warnings else "\n".join([f"- {w}" for w in warnings])
        gap_text = "✔️ Aucun manque dans les rôles." if not gaps else "\n".join([f"- {g}" for g in gaps])
        bp_text = "✔️ Aucune anomalie détectée." if not bp else "\n".join([f"- {i}" for i in bp])

        csv_path = export_csv(df)

        return df, warn_text, gap_text, bp_text, csv_path

    generate_btn.click(
        run,
        inputs=[domain, project, team, env, personas],
        outputs=[df_output, warnings_box, gaps_box, bestpractice_box, csv_file]
    )

app.launch()
