import gradio as gr
import pandas as pd
import tempfile
import html
import shutil
from pathlib import Path
import xml.etree.ElementTree as ET
import vsdx
from vsdx import VisioFile

BASE_DIR = Path(__file__).resolve().parent

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
    "functions": "fnc",
    "ingestion": "ing",
    "consommation": "csm",
    "bi": "bi",
    "ia": "cog"
}

DEFAULT_ENVIRONMENTS = ["dev", "qa", "preprod", "prod"]

# ===========================================
#   COULEURS PAR CATÉGORIE (style Azure)
# ===========================================

CATEGORY_COLOR = {
    "synapse": "#3B9AFF",        # Bleu Synapse
    "sql_db": "#003B75",         # SQL DB (bleu foncé)
    "sql_rbac": "#003B75",       # SQL RBAC (même couleur)
    "storage_data": "#00A1A7",   # Storage Data (turquoise)
    "storage_mgmt": "#007C7C",   # Storage Mgmt (teal)
    "ml": "#7F47DD",             # Azure ML (violet)
    "monitoring": "#00A65A",     # Monitor / Log Analytics (vert)
    "network": "#0099D5",        # Networking (bleu cyan)
    "functions": "#FFB300",      # Functions (jaune)
    "security": "#D64545",       # Security (rouge)
    "global": "#D0D6E3",         # Global (gris Azure)
}

# Références : Microsoft Well-Architected "Architecture design diagrams"
# https://learn.microsoft.com/en-us/azure/well-architected/architect-role/design-diagrams
CATEGORY_DISPLAY_LABELS = {
    "synapse": "Azure Synapse Analytics",
    "sql_db": "Azure SQL Database",
    "sql_rbac": "Azure SQL Server",
    "storage_data": "Azure Storage Data Plane",
    "storage_mgmt": "Azure Storage Management",
    "ml": "Azure Machine Learning",
    "monitoring": "Azure Monitor / Log Analytics",
    "network": "Azure Virtual Network",
    "functions": "Azure Functions",
    "security": "Microsoft Defender for Cloud",
    "global": "Azure Subscription",
    "eventhub": "Azure Event Hubs",
    "datafactory": "Azure Data Factory",
}

AZURE_BRAND_COLORS = {
    "persona_border": "#0078D4",
    "persona_fill": "#EDF7FF",
    "section_border": "#5B8DEF",
    "section_fill": "#F5F8FF",
    "st_border": "#004C99",
    "st_fill": "#E6F2FF",
    "sr_border": "#106EBE",
    "sr_fill": "#F6F9FF",
}

VISIO_TEMPLATE_PATH = BASE_DIR / "templates" / "azure_blueprint_template.vsdx"

# ===========================================
#   SHAPES OFFICIELS AZURE POUR DRAW.IO
#   (palette "Azure 2023" de diagrams.net)
# ===========================================
CRIT_COLORS = {
    "Important": "#ffb3b3",    # rouge clair
    "Standard":  "#b3d1ff",    # bleu clair
    "Lecture":   "#b3e6b3",    # vert clair
}
PIM_REQUIRED = {
    "Contributor",
    "Storage Blob Data Owner",
    "Synapse Administrator",
    "SQL DB Contributor",
    "SQL Server Contributor",
    "User Access Administrator",
    "Network Contributor",
}

AZURE_CATEGORY_TO_SHAPE = {
    "global": "mxgraph.azure2.general.subscription",
    "storage_data": "mxgraph.azure2.storage.blob_storage",
    "storage_mgmt": "mxgraph.azure2.storage.storage_account",
    "synapse": "mxgraph.azure2.analytics.synapse",
    "sql_rbac": "mxgraph.azure2.databases.sql_server",
    "sql_db": "mxgraph.azure2.databases.sql_database",
    "ml": "mxgraph.azure2.ai.machine_learning",
    "functions": "mxgraph.azure2.compute.function_apps",
    "monitoring": "mxgraph.azure2.monitor.monitor",
    "network": "mxgraph.azure2.network.vnet",
    "security": "mxgraph.azure2.security.security_center",
    "eventhub": "mxgraph.azure2.integration.event_hub",
    "datafactory": "mxgraph.azure2.integration.data_factory",
}

AZURE_ICON_PATHS = {
    "global": "img/lib/azure2/general/Subscriptions.svg",
    "storage_data": "img/lib/azure2/storage/Storage_Accounts.svg",
    "storage_mgmt": "img/lib/azure2/storage/Storage_Explorer.svg",
    "synapse": "img/lib/azure2/analytics/Azure_Synapse_Analytics.svg",
    "sql_rbac": "img/lib/azure2/databases/SQL_Server.svg",
    "sql_db": "img/lib/azure2/databases/SQL_Database.svg",
    "ml": "img/lib/azure2/ai/Azure_Machine_Learning.svg",
    "functions": "img/lib/azure2/compute/Azure_Functions.svg",
    "monitoring": "img/lib/azure2/analytics/Log_Analytics_Workspace.svg",
    "network": "img/lib/azure2/networking/Virtual_Networks.svg",
    "security": "img/lib/azure2/security/Defender.svg",
    "eventhub": "img/lib/azure2/integration/Event_Hubs.svg",
    "datafactory": "img/lib/azure2/integration/Data_Factory.svg",
    "keyvault": "img/lib/azure2/security/Key_Vaults.svg",
}
DEFAULT_AZURE_ICON = "img/lib/azure2/general/Resource_Groups.svg"

SHAPE_PERSONA = "mxgraph.azure2.general.user"
SHAPE_GRT = "mxgraph.azure2.general.subscription"
SHAPE_GRR = "mxgraph.azure2.general.resource_group"

LEGEND_ITEMS = [
    ("Persona", SHAPE_PERSONA),
    ("Profil applicatif (GRT)", SHAPE_GRT),
    ("Groupe de rôle (GRR / SR)", SHAPE_GRR),
    ("Synapse", AZURE_CATEGORY_TO_SHAPE.get("synapse")),
    ("SQL DB", AZURE_CATEGORY_TO_SHAPE.get("sql_db")),
    ("SQL RBAC", AZURE_CATEGORY_TO_SHAPE.get("sql_rbac")),
    ("Storage Data", AZURE_CATEGORY_TO_SHAPE.get("storage_data")),
    ("Storage Mgmt", AZURE_CATEGORY_TO_SHAPE.get("storage_mgmt")),
    ("Azure ML", AZURE_CATEGORY_TO_SHAPE.get("ml")),
    ("Functions", AZURE_CATEGORY_TO_SHAPE.get("functions")),
    ("Monitoring", AZURE_CATEGORY_TO_SHAPE.get("monitoring")),
    ("Network", AZURE_CATEGORY_TO_SHAPE.get("network")),
    ("Security", AZURE_CATEGORY_TO_SHAPE.get("security")),
    ("Event Hub", AZURE_CATEGORY_TO_SHAPE.get("eventhub")),
    ("Data Factory", AZURE_CATEGORY_TO_SHAPE.get("datafactory")),
]

ET.register_namespace("", "http://schemas.microsoft.com/office/visio/2012/main")
ET.register_namespace("r", "http://schemas.openxmlformats.org/officeDocument/2006/relationships")

BASE_DIR = Path(__file__).resolve().parent

# ===========================================
#   RACCOURCISSEMENT (max 8 chars)
# ===========================================

def shorten(value, max_len=8):
    if not value:
        return ""
    return value.lower().replace(" ", "").replace("-", "").replace("_", "")[:max_len]


# ===========================================
#   ROLES MICROSOFT (catalogue enrichi)
#   Sources :
#   - https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
#   - https://learn.microsoft.com/en-us/azure/synapse-analytics/security/how-to-set-up-access-control
#   - https://learn.microsoft.com/en-us/azure/machine-learning/how-to-assign-roles
# ===========================================

ROLE_CATALOG = {
    "global": ["Owner", "Contributor", "Reader", "User Access Administrator"],
    "storage_data": [
        "Storage Blob Data Owner",
        "Storage Blob Data Contributor",
        "Storage Blob Data Reader",
        "Storage Blob Delegator",
        "Storage Queue Data Contributor",
        "Storage Queue Data Message Processor",
        "Storage Queue Data Message Sender",
        "Storage Queue Data Reader",
        "Storage Queue Delegator",
        "Storage Table Data Contributor",
        "Storage Table Data Reader",
        "Storage Table Delegator",
        "Storage File Data Privileged Contributor",
        "Storage File Data Privileged Reader",
        "Storage File Data SMB Admin",
        "Storage File Data SMB Share Contributor",
        "Storage File Data SMB Share Elevated Contributor",
        "Storage File Data SMB Share Reader",
        "Storage File Data SMB Take Ownership",
        "Storage File Delegator"
    ],
    "storage_mgmt": [
        "Storage Account Contributor",
        "Storage Account Key Operator Service Role",
        "Storage Account Backup Contributor",
        "Classic Storage Account Contributor",
        "Classic Storage Account Key Operator Service Role"
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
        "Website Contributor",
        "Web Plan Contributor"
    ],
    "monitoring": [
        "Monitoring Contributor",
        "Monitoring Reader",
        "Monitoring Metrics Publisher",
        "Log Analytics Data Reader",
        "Log Analytics Reader",
        "Log Analytics Contributor"
    ],
    "security": [
        "Security Reader",
        "Security Admin",
        "Security Assessment Contributor"
    ],
    "network": [
        "Network Contributor",
        "Classic Network Contributor",
        "DNS Zone Contributor",
        "Private DNS Zone Contributor"
    ],
    "eventhub": [
        "Azure Event Hubs Data Owner",
        "Azure Event Hubs Data Sender",
        "Azure Event Hubs Data Receiver"
    ],
    "keyvault": [
        "Key Vault Administrator",
        "Key Vault Certificates Officer",
        "Key Vault Certificates User",
        "Key Vault Contributor",
        "Key Vault Crypto Officer",
        "Key Vault Crypto Service Encryption User",
        "Key Vault Crypto Service Release User",
        "Key Vault Crypto User",
        "Key Vault Data Access Administrator",
        "Key Vault Reader",
        "Key Vault Secrets Officer",
        "Key Vault Secrets User"
    ],
    "datafactory": [
        "Data Factory Contributor",
        "Data Factory Reader"
    ]
}

# ===========================================
#   CONTRAINTES ENVIRONNEMENTALES
# ===========================================

ROLE_ENV_CONSTRAINTS = {
    ("global", "Reader"): {
        "only": ["prod"],
        "note": "Les accès Readers globaux sont réservés à la production."
    }
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
#   ROLES CUSTOM MICROSOFT (domaines valorisés)
# ===========================================

CUSTOM_ROLE_BUNDLES = {
    "platform-ops": {
        "synapse": ["Platform Synapse Admin"],
        "ingestion": ["Platform Storage Steward"],
        "consommation": ["Platform SQL Custodian"],
        "bi": ["Platform Monitoring Publisher"],
        "ml": ["Platform ML Supervisor"],
        "ia": ["Platform Cognitive Governor"]
    },
    "data-engineer": {
        "synapse": ["DE Synapse Contributor"],
        "ingestion": ["DE Data Factory Orchestrator"],
        "consommation": ["DE SQL Data Builder"],
        "bi": ["DE Dataset Stager"],
        "ml": ["DE Feature Pipeline Operator"],
        "ia": ["DE Cognitive Enabler"]
    },
    "data-scientist": {
        "synapse": ["DS Synapse Reader"],
        "ingestion": ["DS Landing Reader"],
        "consommation": ["DS SQL Consumer"],
        "bi": ["DS Insight Viewer"],
        "ml": ["DS Experiment Author"],
        "ia": ["DS Cognitive User"]
    },
    "bi-analyst": {
        "synapse": ["BI Warehouse Viewer"],
        "ingestion": ["BI Landing Consumer"],
        "consommation": ["BI SQL Reader"],
        "bi": ["BI Content Publisher"],
        "ml": ["BI Feature Consumer"],
        "ia": ["BI Cognitive Visuals"]
    },
    "support-engineer": {
        "synapse": ["Support Synapse Monitor"],
        "ingestion": ["Support Storage Monitor"],
        "consommation": ["Support SQL Auditor"],
        "bi": ["Support BI Observer"],
        "ml": ["Support ML Reviewer"],
        "ia": ["Support Cognitive Auditor"]
    }
}


# ===========================================
#   HELPERS (roles + nomenclature)
# ===========================================

def default_custom_role_name(persona, category):
    persona_label = persona.replace("-", " ").title()
    category_label = category.replace("_", " ").title()
    return f"{persona_label} {category_label} Custom"


def assemble_persona_roles(persona, custom_only=False):
    combined = {}
    sources = []

    if not custom_only:
        sources.append(PERSONA_BUNDLES.get(persona, {}).get("roles", {}))

    sources.append(CUSTOM_ROLE_BUNDLES.get(persona, {}))

    for source in sources:
        for category, role_list in source.items():
            combined.setdefault(category, [])
            for role in role_list:
                name = (role or "").strip()
                if not name:
                    name = default_custom_role_name(persona, category)
                if name not in combined[category]:
                    combined[category].append(name)
    return combined


# ===========================================
#   VALIDATION / CONTRAINTES (catalogue + env)
# ===========================================

def role_exists_in_catalog(category, role):
    catalog = ROLE_CATALOG.get(category)
    if catalog is None:
        return True
    return role in catalog


def get_env_constraint(category, role):
    return ROLE_ENV_CONSTRAINTS.get((category, role))


def role_allowed_in_env(category, role, env):
    constraint = get_env_constraint(category, role)
    if not constraint:
        return True

    allowed = constraint.get("only")
    blocked = constraint.get("exclude")

    if allowed and env not in allowed:
        return False
    if blocked and env in blocked:
        return False
    return True


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
    if category == "ingestion":
        return "resource-group"
    if category == "consommation":
        return "workspace"
    if category == "bi":
        return "workspace"
    if category == "ml":
        return "ml-workspace"
    if category == "ia":
        return "resource-group"
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
    critical_keywords = ["Admin", "Custodian", "Governor", "Supervisor"]
    if any(keyword.lower() in role.lower() for keyword in critical_keywords):
        return "Critique (PIM requis)"
    important_keywords = ["Contributor", "Operator", "Publisher", "Builder", "Author", "Orchestrator"]
    if any(keyword.lower() in role.lower() for keyword in important_keywords):
        return "Important"
    return "Standard"


# ===========================================
#   GENERATION GROUPES
# ===========================================

def generate_group_profile(domain, project, team, persona, env):
    return f"st-{shorten(domain)}-{shorten(project)}-{shorten(team)}-{shorten(persona)}"

def generate_group_role(domain, project, team, persona, category, env):
    return f"sr-{shorten(domain)}-{shorten(project)}-{shorten(team)}-{shorten(persona)}-{CATEGORY_ABBR.get(category, category[:3])}-{env}"


# ===========================================
#   GAP ANALYSIS
# ===========================================

def gap_analysis(persona, category, roles):
    missing = []
    if persona == "data-scientist" and category == "synapse" and "Synapse Artifact User" not in roles:
        missing.append("Synapse Artifact User conseillé pour les DS")
    if persona == "data-engineer" and category == "synapse" and "Synapse Linked Data Manager" not in roles:
        missing.append("Synapse Linked Data Manager conseillé pour les DE")
    return missing


# ===========================================
#   BEST PRACTICES CHECKS
# ===========================================

def best_practice_checks(df):
    if df is None or df.empty:
        return []

    checks = []

    # 1. Trop de permissions par ST
    bloated = df.groupby(["Env", "GRT"])["Rôle"].count()
    for (env, st), count in bloated.items():
        if count > 35:
            checks.append(f"⚠️ {st} contient {count} permissions (role bloat) sur {env}.")

    # 2. PIM requis
    critical_mask = df["Criticité"].fillna("").str.contains("Critique")
    for _, row in df[critical_mask].iterrows():
        checks.append(f"🔒 Rôle critique sans PIM : {row['Rôle']} ({row['Persona']} - {row['Env']})")

    # 3. Storage Owner
    for _, row in df[df["Rôle"] == "Storage Blob Data Owner"].iterrows():
        checks.append(f"⚠️ Storage Blob Data Owner accordé à {row['Persona']} ({row['Env']}) — très puissant.")

    # 4. Key Vault access
    kv = df[df["Rôle"] == "Key Vault Secrets Officer"]
    for _, row in kv.iterrows():
        checks.append(f"⚠️ Key Vault Secrets Officer très sensible : {row['Persona']} ({row['Env']})")

    return checks


# ===========================================
#   GENERATION DU TABLEAU (inclut df_grouped)
# ===========================================

def generate_table(domain, project, team, personas, envs=None):
    raw_rows = []
    warnings = []
    gaps = []
    personas = personas or []
    envs = envs or DEFAULT_ENVIRONMENTS
    catalog_warnings = set()
    constraint_notices = set()

    for persona in personas:
        persona_roles = PERSONA_BUNDLES.get(persona, {}).get("roles", {})

        for cat, roles in persona_roles.items():
            gaps += gap_analysis(persona, cat, roles)

        for env in envs:
            grt = generate_group_profile(domain, project, team, persona, env)

            if len(grt) > 63:
                warnings.append(f"GRT trop long ({len(grt)}): {grt}")

            for category, role_list in persona_roles.items():
                grr = generate_group_role(domain, project, team, persona, category, env)
                if len(grr) > 63:
                    warnings.append(f"GRR trop long ({len(grr)}): {grr}")

                for role in role_list:
                    if not role_exists_in_catalog(category, role):
                        key = (persona, category, role)
                        if key not in catalog_warnings:
                            catalog_warnings.add(key)
                            warnings.append(
                                f"{persona}: rôle '{role}' introuvable dans le catalogue Azure '{category}'."
                            )
                        continue

                    if not role_allowed_in_env(category, role, env):
                        constraint = get_env_constraint(category, role) or {}
                        allowed = constraint.get("only")
                        excluded = constraint.get("exclude")
                        note = constraint.get("note", "")
                        key = (persona, category, role, env)
                        if key not in constraint_notices:
                            constraint_notices.add(key)
                            if allowed:
                                allowed_txt = ", ".join(allowed)
                                warnings.append(
                                    f"{persona}: rôle '{role}' ({category}) limité aux envs {allowed_txt}; ignoré pour {env}. {note}".strip()
                                )
                            elif excluded:
                                excluded_txt = ", ".join(excluded)
                                warnings.append(
                                    f"{persona}: rôle '{role}' ({category}) interdit sur {excluded_txt}; ignoré pour {env}. {note}".strip()
                                )
                            else:
                                warnings.append(
                                    f"{persona}: rôle '{role}' ({category}) restreint pour {env}. {note}".strip()
                                )
                        continue

                    raw_rows.append({
                        "Env": env,
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

    if df_raw.empty:
        columns = [
            "Env",
            "Persona",
            "GRT",
            "GRR",
            "Catégorie",
            "Rôle",
            "Scope recommandé",
            "Niveau d’accès",
            "Criticité",
            "Len(GRT)",
            "Len(GRR)"
        ]
        return pd.DataFrame(columns=columns), warnings, gaps

    # === REGROUPEMENT POUR AGRÉGER LES RÔLES ===
    df_grouped = (
        df_raw
        .groupby(["Env", "Persona", "GRT", "GRR", "Catégorie"])
        .agg({
            "Rôle": lambda x: ", ".join(sorted(set(x))),
            "Scope recommandé": lambda x: ", ".join(sorted(set(x))),
            "Niveau d’accès": lambda x: ", ".join(sorted(set(x))),
            "Criticité": lambda x: ", ".join(sorted(set(x))),
            "Len(GRT)": "first",
            "Len(GRR)": "first",
        })
        .reset_index()
    )

    df_grouped = df_grouped[
        [
            "Env",
            "Persona",
            "GRT",
            "GRR",
            "Catégorie",
            "Rôle",
            "Scope recommandé",
            "Niveau d’accès",
            "Criticité",
            "Len(GRT)",
            "Len(GRR)"
        ]
    ]

    return df_grouped, warnings, gaps

# ===========================================
#   EXPORT MERMAID
# ===========================================
def export_mermaid(df):
    if df.empty:
        return "graph TD"

    lines = ["graph TD"]

    for env in df["Env"].unique():
        env_block = df[df["Env"] == env]
        lines.append(f"    subgraph {env}")

        for persona in env_block["Persona"].unique():
            persona_id = f"{env}_{persona}".replace("-", "_")
            lines.append(f'        {persona_id}["Persona: {persona}"]')

            # GRT unique du persona
            grt = env_block[env_block["Persona"] == persona]["GRT"].iloc[0]
            grt_id = f"{env}_{grt}".replace("-", "_")
            lines.append(f'        {persona_id} --> {grt_id}["{grt}"]')

            persona_df = env_block[env_block["Persona"] == persona]
            for _, row in persona_df.iterrows():
                grr_id = f"{env}_{row['GRR']}".replace("-", "_")
                roles = row["Rôle"].replace(",", "<br>")
                label = f"{row['Catégorie']}<br>{roles}"
                lines.append(f'        {grt_id} --> {grr_id}["{label}"]')

        lines.append("    end")

    return "\n".join(lines)
# ===========================================
#   EXPORT DRAWIO
# ===========================================

def export_drawio(df):
    """
    Génère un diagramme Draw.io entièrement stylé Azure :
    - swimlanes par persona
    - icônes Azure officielles
    - criticité colorée
    - annotation PIM auto
    - 1 feuille par environnement
    """

    def clean_value(value):
        if value is None:
            return ""
        value = str(value).replace("<br/>", "\n").replace("<br>", "\n")
        return html.escape(value, quote=True).replace("\n", "&#xa;")

    def cell(id, value, x, y, w, h, style, parent="1"):
        safe_value = clean_value(value)
        return f"""
        <mxCell id="{id}" value="{safe_value}" style="{style}" vertex="1" parent="{parent}">
            <mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/>
        </mxCell>
        """

    def edge(id, source, target, parent="1"):
        return f"""
        <mxCell id="{id}" edge="1" source="{source}" target="{target}" parent="{parent}">
            <mxGeometry relative="1" as="geometry"/>
        </mxCell>
        """

    def build_env_diagram(env_df, env, diagram_idx):
        xml_cells = []
        edges = []
        swimlane_x = 20
        swimlane_width = 1600
        lane_margin = 40
        current_y = 20
        row_gap = 130
        header_offset = 200
        node_height = 80
        edge_id = 9000

        personas = env_df["Persona"].unique()

        for persona in personas:
            dfp = env_df[env_df["Persona"] == persona]
            row_count = max(len(dfp), 1)
            lane_height = max(320, header_offset + row_count * row_gap + 60)
            lane_top = current_y

            swimlane_style = "swimlane;fontSize=14;horizontal=0;rounded=1;container=1;collapsible=0;"
            lane_id = f"lane_{env}_{persona}"
            xml_cells.append(cell(lane_id, f"Persona: {persona}", swimlane_x, lane_top, swimlane_width, lane_height, swimlane_style))

            def lane_cell(cell_id, value, abs_x, abs_y, w, h, style):
                rel_x = abs_x - swimlane_x
                rel_y = abs_y - lane_top
                xml_cells.append(cell(cell_id, value, rel_x, rel_y, w, h, style, parent=lane_id))

            grt_value = dfp["GRT"].iloc[0]
            grt_id = f"grt_{env}_{persona}"
            grt_style = f"shape={SHAPE_GRT};whiteSpace=wrap;html=1;strokeColor=#004c99;fillColor=#e6f2ff;fontSize=13;"
            lane_cell(grt_id, f"ST : {grt_value}", swimlane_x + 240, lane_top + 100, 220, 80, grt_style)

            persona_id = f"persona_{env}_{persona}"
            persona_style = f"shape={SHAPE_PERSONA};whiteSpace=wrap;html=1;fontStyle=1;strokeColor=#0050ef;fillColor=#edf7ff;"
            lane_cell(persona_id, f"{persona} ({env})", swimlane_x + 20, lane_top + 100, 200, 80, persona_style)

            edges.append(edge(edge_id, persona_id, grt_id, parent=lane_id)); edge_id += 1

            y_cursor = lane_top + header_offset

            for idx, row in dfp.reset_index(drop=True).iterrows():
                cat = row["Catégorie"]
                grr = row["GRR"]
                role = row["Rôle"]
                criticite = row["Criticité"]
                is_pim = any(r.strip() in PIM_REQUIRED for r in role.split(","))

                label = f"{cat} : {role}"
                if is_pim:
                    label += " (PIM)"

                color = CRIT_COLORS.get(criticite, "#ffffff")

                sr_id = f"sr_{env}_{persona}_{cat}_{idx}"
                sr_style = f"shape={SHAPE_GRR};whiteSpace=wrap;html=1;fontSize=12;strokeColor=#004c99;fillColor=#f8fbff;"
                lane_cell(sr_id, f"SR : {grr}", swimlane_x + 500, y_cursor, 240, node_height, sr_style)

                resource_id = f"resource_{env}_{persona}_{cat}_{idx}"
                resource_label = cat.replace("_", " ").title()
                icon_path = AZURE_ICON_PATHS.get(cat, DEFAULT_AZURE_ICON)
                resource_style = (
                    "shape=image;whiteSpace=wrap;html=1;"
                    "verticalLabelPosition=bottom;labelPosition=center;"
                    "verticalAlign=top;align=center;imageAspect=1;"
                    f"image={icon_path};fontSize=12;"
                )
                lane_cell(resource_id, resource_label, swimlane_x + 780, y_cursor - 10, 150, 110, resource_style)

                role_id = f"role_{env}_{persona}_{cat}_{idx}"
                style_role = f"rounded=1;whiteSpace=wrap;html=1;fillColor={color};strokeColor=#333333;fontSize=12;"
                lane_cell(role_id, label, swimlane_x + 1040, y_cursor, 320, node_height, style_role)

                edges.append(edge(edge_id, grt_id, sr_id, parent=lane_id)); edge_id += 1
                edges.append(edge(edge_id, sr_id, resource_id, parent=lane_id)); edge_id += 1
                edges.append(edge(edge_id, resource_id, role_id, parent=lane_id)); edge_id += 1

                y_cursor += row_gap

            current_y += lane_height + lane_margin

        diagram = f"""
        <diagram id="env_{diagram_idx}" name="{env.upper()}">
            <mxGraphModel>
                <root>
                    <mxCell id="0"/>
                    <mxCell id="1" parent="0"/>
                    {''.join(xml_cells)}
                    {''.join(edges)}
                </root>
            </mxGraphModel>
        </diagram>
        """
        return diagram

    if df.empty:
        return """
        <mxfile host="app.diagrams.net">
            <diagram id="empty" name="RBAC">
                <mxGraphModel>
                    <root>
                        <mxCell id="0"/>
                        <mxCell id="1" parent="0"/>
                    </root>
                </mxGraphModel>
            </diagram>
        </mxfile>
        """

    diagrams = []
    for idx, env in enumerate(df["Env"].unique()):
        env_df = df[df["Env"] == env]
        if env_df.empty:
            continue
        diagrams.append(build_env_diagram(env_df, env, idx))

    drawio = f"""
    <mxfile host="app.diagrams.net">
        {''.join(diagrams)}
    </mxfile>
    """

    return drawio


# ===========================================
#   EXPORT VISIO (VSDX)
# ===========================================


VISIO_NS = "http://schemas.microsoft.com/office/visio/2012/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def ns(tag):
    return f"{{{VISIO_NS}}}{tag}"


def export_visio(df):
    """Génère un Visio multi-feuilles en s'appuyant sur le template officiel
    embarqué dans le package `vsdx` (structure conforme à Microsoft)."""
    if df.empty:
        return None

    template_path = VISIO_TEMPLATE_PATH if VISIO_TEMPLATE_PATH.exists() else Path(vsdx.__file__).resolve().parent / "media" / "media.vsdx"
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".vsdx")
    tmp.close()
    shutil.copyfile(template_path, tmp.name)

    envs = [env for env in df["Env"].unique() if not df[df["Env"] == env].empty]
    if not envs:
        return None

    with VisioFile(tmp.name) as vis:
        base_pages = list(vis.pages)
        if not base_pages:
            raise RuntimeError("Le template Visio ne contient aucune page de base.")

        # conserver la première page comme gabarit, supprimer le reste
        for extra_page in base_pages[1:]:
            vis.remove_page_by_index(extra_page.index_num)

        def hydrate_page(page_obj, env_name, env_df):
            page_element, page_width, page_height = build_visio_page(env_name, env_df)
            page_obj.name = env_name.upper()
            page_obj.width = page_width
            page_obj.height = page_height
            page_obj.xml = ET.ElementTree(page_element)

        first_env = envs[0]
        first_df = df[df["Env"] == first_env]
        hydrate_page(base_pages[0], first_env, first_df)

        for env in envs[1:]:
            env_df = df[df["Env"] == env]
            new_page = vis.add_page(name=env.upper())
            # synchroniser l'identifiant de page nouvellement créé
            latest_page = vis.pages_xml.getroot().findall(ns("Page"))[-1]
            new_page.page_id = latest_page.attrib.get("ID", "")
            hydrate_page(new_page, env, env_df)

        vis.save_vsdx(tmp.name)

    return tmp.name


def visio_color(hex_color):
    if not hex_color:
        return "#ffffff"
    value = hex_color.lstrip("#")
    if len(value) != 6:
        return "#ffffff"
    return f"#{value.lower()}"


def sanitize_visio_text(text):
    if not text:
        return ""
    return str(text)


def build_visio_page(env, env_df):
    personas = []
    for persona in env_df["Persona"].unique():
        block = env_df[env_df["Persona"] == persona].reset_index(drop=True)
        personas.append((persona, block))

    page_width = 16.5
    header_height = 1.1
    row_gap = 1.3
    lane_padding = 0.45
    lane_gap = 0.9
    bottom_padding = 0.8
    top_padding = 1.0

    lane_metrics = []
    total_height = top_padding
    for persona, block in personas:
        rows = max(len(block), 1)
        height = lane_padding * 2 + header_height + rows * row_gap + bottom_padding
        lane_metrics.append((persona, block, rows, height))
        total_height += height + lane_gap

    page_height = max(12.0, total_height)
    current_top = page_height - 0.7
    shapes = []
    shape_id = 1

    columns = {
        "persona": {"x": 1.8, "width": 2.4},
        "grt": {"x": 4.7, "width": 2.6},
        "sr": {"x": 7.7, "width": 2.4},
        "resource": {"x": 10.3, "width": 2.4},
        "role": {"x": 13.6, "width": 3.6},
    }

    def add_shape(shape):
        nonlocal shape_id
        shape["id"] = shape_id
        shapes.append(shape)
        shape_id += 1
        return shape_id - 1

    def rect_shape(pin_x, pin_y, width, height, text, fill, stroke="#004c99", font_size=10, bold=False, rounding=0.15, stroke_weight=0.02):
        return {
            "type": "rect",
            "pin_x": pin_x,
            "pin_y": pin_y,
            "width": width,
            "height": height,
            "text": text,
            "fill": fill,
            "stroke": stroke,
            "font_size": font_size,
            "bold": bold,
            "rounding": rounding,
            "stroke_weight": stroke_weight,
        }

    def connector_segment(x_start, x_end, y, color, height=0.18):
        width = max((x_end - x_start) - 0.4, 0.3)
        bar = rect_shape(
            pin_x=x_start + width / 2 + 0.2,
            pin_y=y,
            width=width,
            height=height,
            text="",
            fill=color,
            stroke=color,
            stroke_weight=height / 5,
        )
        add_shape(bar)
        arrow = arrow_shape(
            pin_x=x_end - 0.35,
            pin_y=y,
            width=0.45,
            height=0.35,
            fill=color,
            stroke=color,
        )
        add_shape(arrow)

    def arrow_shape(pin_x, pin_y, width=0.35, height=0.25, fill="#004c99", stroke="#004c99"):
        return {
            "type": "arrow",
            "pin_x": pin_x,
            "pin_y": pin_y,
            "width": width,
            "height": height,
            "fill": fill,
            "stroke": stroke,
        }

    title_shape = rect_shape(
        pin_x=page_width / 2,
        pin_y=page_height - 0.4,
        width=6.5,
        height=0.8,
        text=f"Plan RBAC – {env.upper()}",
        fill=AZURE_BRAND_COLORS["st_fill"],
        stroke=AZURE_BRAND_COLORS["st_border"],
        font_size=12,
        bold=True,
        stroke_weight=0.03,
    )
    add_shape(title_shape)

    for persona, block, rows, block_height in lane_metrics:
        lane_top = current_top
        lane_center = lane_top - block_height / 2
        lane_shape = rect_shape(
            pin_x=page_width / 2,
            pin_y=lane_center,
            width=page_width - 1.0,
            height=block_height,
            text="",
            fill=AZURE_BRAND_COLORS["section_fill"],
            stroke=AZURE_BRAND_COLORS["section_border"],
            stroke_weight=0.04,
            rounding=0.2,
        )
        add_shape(lane_shape)

        persona_center = lane_top - lane_padding - header_height / 2
        persona_shape = rect_shape(
            pin_x=columns["persona"]["x"],
            pin_y=persona_center,
            width=columns["persona"]["width"],
            height=header_height,
            text=f"PERSONA\n{persona.upper()}",
            fill=AZURE_BRAND_COLORS["persona_fill"],
            stroke=AZURE_BRAND_COLORS["persona_border"],
            font_size=11,
            bold=True,
            stroke_weight=0.04,
        )
        add_shape(persona_shape)

        grt_value = block["GRT"].iloc[0]
        grt_shape = rect_shape(
            pin_x=columns["grt"]["x"],
            pin_y=persona_center,
            width=columns["grt"]["width"],
            height=header_height,
            text=f"PROFIL ST\n{grt_value.upper()}",
            fill=AZURE_BRAND_COLORS["st_fill"],
            stroke=AZURE_BRAND_COLORS["st_border"],
            font_size=11,
            bold=True,
            stroke_weight=0.04,
        )
        add_shape(grt_shape)

        persona_end = columns["persona"]["x"] + columns["persona"]["width"] / 2
        grt_start = columns["grt"]["x"] - columns["grt"]["width"] / 2
        connector_segment(persona_end, grt_start, persona_center, AZURE_BRAND_COLORS["persona_border"])

        row_start = persona_center - header_height / 2 - 0.6
        if rows == 0:
            rows = 1

        for row_idx, row in block.iterrows():
            row_y = row_start - row_idx * row_gap
            category = row["Catégorie"]
            grr = row["GRR"]
            role_label = row["Rôle"].replace(",", "\n")
            criticity = row["Criticité"]
            is_pim = "PIM" in criticity or any(r.strip() in PIM_REQUIRED for r in row["Rôle"].split(","))
            resource_label = CATEGORY_DISPLAY_LABELS.get(category, category.replace("_", " ").title())
            role_text = f"{resource_label}\n{role_label}"
            if is_pim and "PIM REQUIS" not in role_text:
                role_text += "\nPIM REQUIS"

            sr_shape = rect_shape(
                pin_x=columns["sr"]["x"],
                pin_y=row_y,
                width=columns["sr"]["width"],
                height=0.9,
                text=f"SR\n{grr.upper()}",
                fill=AZURE_BRAND_COLORS["sr_fill"],
                stroke=AZURE_BRAND_COLORS["sr_border"],
                font_size=10,
                stroke_weight=0.03,
            )
            add_shape(sr_shape)

            icon_fill = CATEGORY_COLOR.get(category, "#f2f2f2")
            resource_shape = rect_shape(
                pin_x=columns["resource"]["x"],
                pin_y=row_y,
                width=columns["resource"]["width"],
                height=0.9,
                text=resource_label.upper(),
                fill=icon_fill,
                stroke="#1e1e1e",
                font_size=10,
                bold=True,
                stroke_weight=0.03,
            )
            add_shape(resource_shape)

            crit_color = CRIT_COLORS.get(criticity, "#ffffff")
            if is_pim:
                crit_color = "#ffd6d6"
            role_shape = rect_shape(
                pin_x=columns["role"]["x"],
                pin_y=row_y,
                width=columns["role"]["width"],
                height=1.0,
                text=role_text.upper(),
                fill=crit_color,
                stroke="#333333",
                font_size=9,
                stroke_weight=0.03,
            )
            add_shape(role_shape)

            connector_segment(columns["grt"]["x"] + columns["grt"]["width"] / 2, columns["sr"]["x"] - columns["sr"]["width"] / 2, row_y, AZURE_BRAND_COLORS["sr_border"])
            connector_segment(columns["sr"]["x"] + columns["sr"]["width"] / 2, columns["resource"]["x"] - columns["resource"]["width"] / 2, row_y, icon_fill)
            connector_segment(columns["resource"]["x"] + columns["resource"]["width"] / 2, columns["role"]["x"] - columns["role"]["width"] / 2, row_y, crit_color)

            if is_pim:
                badge_shape = rect_shape(
                    pin_x=columns["role"]["x"] + columns["role"]["width"] / 2 - 0.4,
                    pin_y=row_y + 0.35,
                    width=0.8,
                    height=0.35,
                    text="PIM",
                    fill="#ffd6d6",
                    stroke="#c0392b",
                    font_size=9,
                    bold=True,
                    rounding=0.1,
                )
                add_shape(badge_shape)

        current_top -= block_height + lane_gap

    page = ET.Element(ns("PageContents"), {"xmlns:r": REL_NS})
    page_sheet = ET.SubElement(page, ns("PageSheet"), {"LineStyle": "0", "FillStyle": "0", "TextStyle": "0"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "PageWidth", "V": str(page_width)})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "PageHeight", "V": str(page_height)})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "ShdwOffsetX", "V": "0"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "ShdwOffsetY", "V": "0"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "PageScale", "U": "MM", "V": "0.03937007874015748"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "DrawingScale", "U": "MM", "V": "0.03937007874015748"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "DrawingSizeType", "V": "0"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "DrawingScaleType", "V": "0"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "InhibitSnap", "V": "0"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "PageLockReplace", "U": "BOOL", "V": "0"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "PageLockDuplicate", "U": "BOOL", "V": "0"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "UIVisibility", "V": "0"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "ShdwType", "V": "0"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "ShdwObliqueAngle", "V": "0"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "ShdwScaleFactor", "V": "1"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "DrawingResizeType", "V": "1"})
    ET.SubElement(page_sheet, ns("Cell"), {"N": "PageShapeSplit", "V": "1"})

    shapes_el = ET.SubElement(page, ns("Shapes"))
    for shape in shapes:
        shapes_el.append(shape_to_element(shape))

    return page, page_width, page_height


def shape_to_element(shape):
    element = ET.Element(ns("Shape"), {"ID": str(shape["id"]), "Type": "Shape"})
    if shape.get("type") == "line":
        element.set("OneD", "1")
    add_cell = lambda name, value: ET.SubElement(element, ns("Cell"), {"N": name, "V": str(value)})

    width = shape.get("width", 1)
    height = shape.get("height", 0.6)
    add_cell("PinX", shape["pin_x"])
    add_cell("PinY", shape["pin_y"])
    add_cell("Width", width)
    add_cell("Height", height)
    add_cell("LocPinX", width / 2)
    add_cell("LocPinY", height / 2)
    add_cell("Angle", 0)
    add_cell("LineColor", visio_color(shape.get("stroke", "#004c99")))

    shape_type = shape.get("type")

    if shape_type == "line":
        add_cell("LineWeight", shape.get("line_weight", 0.04))
        if shape.get("arrow", True):
            add_cell("EndArrow", 3)
        else:
            add_cell("EndArrow", 0)
    else:
        add_cell("FillForegnd", visio_color(shape.get("fill", "#ffffff")))
        add_cell("FillPattern", 31)
        add_cell("Rounding", shape.get("rounding", 0))
        stroke_weight = shape.get("stroke_weight")
        if stroke_weight:
            add_cell("LineWeight", stroke_weight)

    text_value = sanitize_visio_text(shape.get("text", ""))
    if text_value:
        char_section = ET.SubElement(element, ns("Section"), {"N": "Character", "IX": "0"})
        char_row = ET.SubElement(char_section, ns("Row"), {"IX": "0"})
        font_value = shape.get("font", "Calibri")
        size_pt = float(shape.get("font_size", 10))
        size_in = size_pt / 72.0
        ET.SubElement(char_row, ns("Cell"), {"N": "Font", "V": font_value})
        ET.SubElement(char_row, ns("Cell"), {"N": "Size", "U": "IN", "V": f"{size_in:.4f}"})
        if shape.get("bold"):
            ET.SubElement(char_row, ns("Cell"), {"N": "Style", "V": "1"})
        text_el = ET.SubElement(element, ns("Text"))
        text_el.text = text_value

    geom = ET.SubElement(element, ns("Section"), {"N": "Geometry", "IX": "0"})
    if shape_type == "line":
        row = ET.SubElement(geom, ns("Row"), {"T": "MoveTo", "IX": "0"})
        ET.SubElement(row, ns("Cell"), {"N": "X", "V": "0"})
        ET.SubElement(row, ns("Cell"), {"N": "Y", "V": "0"})
        row = ET.SubElement(geom, ns("Row"), {"T": "LineTo", "IX": "1"})
        ET.SubElement(row, ns("Cell"), {"N": "X", "V": str(shape.get("width", 1))})
        ET.SubElement(row, ns("Cell"), {"N": "Y", "V": "0"})
    elif shape_type == "arrow":
        w = width
        h = height
        points = [
            (0, h / 2),
            (w * 0.75, h),
            (w, h / 2),
            (w * 0.75, 0),
            (0, h / 2)
        ]
        for idx, (x, y) in enumerate(points):
            row = ET.SubElement(geom, ns("Row"), {"T": "MoveTo" if idx == 0 else "LineTo", "IX": str(idx)})
            ET.SubElement(row, ns("Cell"), {"N": "X", "V": str(x)})
            ET.SubElement(row, ns("Cell"), {"N": "Y", "V": str(y)})
    else:
        points = [
            (0, 0),
            (shape.get("width", 1), 0),
            (shape.get("width", 1), shape.get("height", 1)),
            (0, shape.get("height", 1)),
            (0, 0),
        ]
        for idx, (x, y) in enumerate(points):
            row = ET.SubElement(geom, ns("Row"), {"T": "MoveTo" if idx == 0 else "LineTo", "IX": str(idx)})
            ET.SubElement(row, ns("Cell"), {"N": "X", "V": str(x)})
            ET.SubElement(row, ns("Cell"), {"N": "Y", "V": str(y)})

    return element




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

def build_app():
    with gr.Blocks(title="Azure RBAC Generator") as app:

        gr.Markdown("# 🔧 Générateur Azure RBAC – regroupement des rôles & exports Visuels")

        # ----------------------------
        #    INPUTS
        # ----------------------------
        with gr.Row():
            domain = gr.Textbox(label="Domaine")
            project = gr.Textbox(label="Projet")
            team = gr.Textbox(label="Équipe")
        with gr.Row():
            envs = gr.CheckboxGroup(
                choices=DEFAULT_ENVIRONMENTS,
                value=DEFAULT_ENVIRONMENTS,
                label="Environnements cibles",
                info="Sélectionnez les environnements à générer (tous par défaut)."
            )

        personas = gr.CheckboxGroup(
            choices=list(PERSONA_BUNDLES.keys()),
            label="Personas"
        )

        # ----------------------------
        #    BOUTONS
        # ----------------------------
        generate_btn = gr.Button("📊 Générer Tableau")
        export_mermaid_btn = gr.Button("📄 Export Mermaid")
        export_drawio_btn = gr.Button("📊 Export Draw.io XML")
        export_visio_btn = gr.Button("📐 Export Visio (.vsdx)")

        # ----------------------------
        #    OUTPUTS
        # ----------------------------
        df_output = gr.DataFrame(interactive=False, label="Résultat consolidé")
        warnings_box = gr.Markdown()
        gaps_box = gr.Markdown()
        bestpractice_box = gr.Markdown()
        csv_file = gr.File(label="Télécharger CSV")

        mermaid_output = gr.Code(label="Diagramme Mermaid", language="markdown")
        drawio_file = gr.File(label="Télécharger fichier .drawio")
        visio_file = gr.File(label="Télécharger fichier Visio (.vsdx)")

        # ----------------------------
        #    CALLBACKS
        # ----------------------------
        def run(domain, project, team, envs, personas):
            df, warnings, gaps = generate_table(domain, project, team, personas, envs)
            bp = best_practice_checks(df)

            warn_text = "✔️ Aucun avertissement." if not warnings else "\n".join([f"- {w}" for w in warnings])
            gap_text = "✔️ Aucun manque dans les rôles." if not gaps else "\n".join([f"- {g}" for g in gaps])
            bp_text = "✔️ Aucune anomalie détectée." if not bp else "\n".join([f"- {i}" for i in bp])

            csv_path = export_csv(df)

            return df, warn_text, gap_text, bp_text, csv_path

        def run_mermaid(domain, project, team, envs, personas):
            df, _, _ = generate_table(domain, project, team, personas, envs)
            return export_mermaid(df)

        def run_drawio(domain, project, team, envs, personas):
            df, _, _ = generate_table(domain, project, team, personas, envs)
            xml = export_drawio(df)
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".drawio")
            with open(tmp.name, "w", encoding="utf-8") as f:
                f.write(xml)
            return tmp.name

        def run_visio(domain, project, team, envs, personas):
            df, _, _ = generate_table(domain, project, team, personas, envs)
            return export_visio(df)

        # ----------------------------
        #    BINDING DES BOUTONS
        # ----------------------------
        generate_btn.click(
            run,
            inputs=[domain, project, team, envs, personas],
            outputs=[df_output, warnings_box, gaps_box, bestpractice_box, csv_file]
        )

        export_mermaid_btn.click(
            run_mermaid,
            inputs=[domain, project, team, envs, personas],
            outputs=[mermaid_output]
        )

        export_drawio_btn.click(
            run_drawio,
            inputs=[domain, project, team, envs, personas],
            outputs=[drawio_file]
        )

        export_visio_btn.click(
            run_visio,
            inputs=[domain, project, team, envs, personas],
            outputs=[visio_file]
        )

    return app


if __name__ == "__main__":
    build_app().launch()
