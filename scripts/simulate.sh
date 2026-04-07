#!/usr/bin/env bash
# =============================================================================
# simulate.sh — Script de simulación de incidentes de seguridad
#
# Demo: "Nadie Apretó un Botón: Respuesta Automática a Incidentes con AWS Nativo"
# Evento: AWS Security Community Ecuador
#
# Flujo del demo:
#   1. Obtiene automáticamente: Detector ID, Instance ID, Account ID
#   2. Crea un hallazgo real en GuardDuty (visible en consola + Security Hub)
#   3. Invoca la Lambda directamente con la instancia real como blanco
#   4. Muestra el SG de la instancia ANTES y DESPUÉS del aislamiento
#   5. Imprime comandos útiles para monitorear el pipeline completo
#
# Uso:
#   chmod +x scripts/simulate.sh && ./scripts/simulate.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║   🚀  Simulador de Incidentes de Seguridad AWS           ║"
echo "  ║   Nadie Apretó un Botón - Incident Response Demo         ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# ── Pre-checks ───────────────────────────────────────────────────────────────
echo -e "${BOLD}[PRE-CHECK]${NC} Verificando pre-requisitos..."

if ! command -v aws &> /dev/null; then
  echo -e "${RED}❌ AWS CLI no está instalado. Instalar: brew install awscli${NC}"
  exit 1
fi

if ! aws sts get-caller-identity &> /dev/null; then
  echo -e "${RED}❌ Sin credenciales AWS válidas. Ejecuta: aws configure${NC}"
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
CURRENT_REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
echo -e "${GREEN}✅ Cuenta: ${BOLD}${ACCOUNT_ID}${NC}${GREEN} | Región: ${BOLD}${CURRENT_REGION}${NC}"
echo ""

# ── PASO 1: Obtener recursos del despliegue CDK ──────────────────────────────
echo -e "${BLUE}${BOLD}[PASO 1/4]${NC} Obteniendo recursos desplegados por CDK..."
echo ""

# Detector de GuardDuty
DETECTOR_ID=$(aws guardduty list-detectors \
  --query 'DetectorIds[0]' --output text \
  --region "${CURRENT_REGION}" 2>/dev/null || echo "")

if [ -z "${DETECTOR_ID}" ] || [ "${DETECTOR_ID}" = "None" ]; then
  echo -e "${RED}❌ No se encontró detector de GuardDuty.${NC}"
  echo "   Ejecuta primero: cdk deploy --all"
  exit 1
fi
echo -e "  ${GREEN}✅ GuardDuty Detector ID : ${BOLD}${DETECTOR_ID}${NC}"

# Instance ID de la instancia víctima (output del EC2DemoStack)
INSTANCE_ID=$(aws cloudformation describe-stacks \
  --stack-name EC2DemoStack \
  --query "Stacks[0].Outputs[?OutputKey=='DemoInstanceId'].OutputValue" \
  --output text \
  --region "${CURRENT_REGION}" 2>/dev/null || echo "")

if [ -z "${INSTANCE_ID}" ] || [ "${INSTANCE_ID}" = "None" ]; then
  echo -e "${RED}❌ No se encontró la instancia EC2 de demo.${NC}"
  echo "   Ejecuta primero: cdk deploy EC2DemoStack"
  exit 1
fi
echo -e "  ${GREEN}✅ Instancia víctima ID  : ${BOLD}${INSTANCE_ID}${NC}"
echo ""

# ── PASO 2: Estado ANTES del aislamiento ─────────────────────────────────────
echo -e "${BLUE}${BOLD}[PASO 2/4]${NC} Estado de la instancia ${BOLD}ANTES${NC} del aislamiento:"
echo ""

SG_BEFORE=$(aws ec2 describe-instances \
  --instance-ids "${INSTANCE_ID}" \
  --query 'Reservations[0].Instances[0].SecurityGroups[*].{ID:GroupId,Nombre:GroupName}' \
  --output table \
  --region "${CURRENT_REGION}")
echo "${SG_BEFORE}"
echo ""

# ── PASO 3: Crear hallazgo en GuardDuty ──────────────────────────────────────
FINDING_TYPE="Backdoor:EC2/C&CActivity.B"

echo -e "${BLUE}${BOLD}[PASO 3/4]${NC} Creando hallazgo en GuardDuty + invocando Lambda..."
echo ""
echo -e "  Amenaza    : ${YELLOW}${BOLD}${FINDING_TYPE}${NC}"
echo -e "  Severidad  : ${RED}${BOLD}HIGH (7.6)${NC} — Command & Control activo"
echo -e "  Blanco     : ${BOLD}${INSTANCE_ID}${NC}"
echo ""

# Crear hallazgo de muestra (aparece en GuardDuty y Security Hub)
aws guardduty create-sample-findings \
  --detector-id "${DETECTOR_ID}" \
  --finding-types "${FINDING_TYPE}" \
  --region "${CURRENT_REGION}" > /dev/null

echo -e "  ${GREEN}✅ Hallazgo creado en GuardDuty${NC}"

# Invocar la Lambda directamente con el Instance ID real
# (el sample finding usa i-99999999, por eso invocamos directamente)
PAYLOAD=$(cat <<EOF
{
  "detail": {
    "id": "demo-finding-$(date +%s)",
    "type": "${FINDING_TYPE}",
    "severity": 7.6,
    "accountId": "${ACCOUNT_ID}",
    "region": "${CURRENT_REGION}",
    "resource": {
      "resourceType": "Instance",
      "instanceDetails": {
        "instanceId": "${INSTANCE_ID}"
      }
    }
  }
}
EOF
)

echo -e "  ${YELLOW}⏳ Invocando Lambda de aislamiento...${NC}"

LAMBDA_RESPONSE=$(aws lambda invoke \
  --function-name incident-response-isolate-resource \
  --region "${CURRENT_REGION}" \
  --cli-binary-format raw-in-base64-out \
  --payload "${PAYLOAD}" \
  /tmp/lambda-out.json 2>&1)

STATUS_CODE=$(echo "${LAMBDA_RESPONSE}" | grep -o '"StatusCode": [0-9]*' | grep -o '[0-9]*' || echo "0")

if [ "${STATUS_CODE}" = "200" ]; then
  echo -e "  ${GREEN}✅ Lambda ejecutada exitosamente (HTTP ${STATUS_CODE})${NC}"
else
  echo -e "  ${RED}⚠️  Lambda respondió con status ${STATUS_CODE}${NC}"
  cat /tmp/lambda-out.json
fi
echo ""

# ── PASO 4: Estado DESPUÉS del aislamiento ───────────────────────────────────
echo -e "${BLUE}${BOLD}[PASO 4/4]${NC} Estado de la instancia ${BOLD}DESPUÉS${NC} del aislamiento:"
echo ""

# Esperar 3 segundos para que AWS propague el cambio de SG
sleep 3

SG_AFTER=$(aws ec2 describe-instances \
  --instance-ids "${INSTANCE_ID}" \
  --query 'Reservations[0].Instances[0].SecurityGroups[*].{ID:GroupId,Nombre:GroupName}' \
  --output table \
  --region "${CURRENT_REGION}")
echo "${SG_AFTER}"
echo ""

# Mostrar reglas del SG de cuarentena (deberían ser vacías)
QUARANTINE_SG_ID=$(aws ec2 describe-instances \
  --instance-ids "${INSTANCE_ID}" \
  --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' \
  --output text \
  --region "${CURRENT_REGION}")

echo -e "  Reglas del SG de cuarentena ${BOLD}${QUARANTINE_SG_ID}${NC}:"
aws ec2 describe-security-groups \
  --group-ids "${QUARANTINE_SG_ID}" \
  --query 'SecurityGroups[0].{Ingress:IpPermissions,Egress:IpPermissionsEgress}' \
  --output table \
  --region "${CURRENT_REGION}" 2>/dev/null || echo "  (sin reglas — instancia completamente aislada)"
echo ""

# ── Resumen y comandos útiles ─────────────────────────────────────────────────
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}${BOLD}  QUÉ REVISAR EN LA CONSOLA AWS${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}  1. GuardDuty${NC}    → Security > GuardDuty > Findings > Severity=High"
echo -e "${CYAN}  2. Security Hub${NC} → Security > Security Hub > Findings > Product=GuardDuty"
echo -e "${CYAN}  3. EventBridge${NC}  → App Integration > EventBridge > Rules > guardduty-high-severity-findings > Monitoring"
echo -e "${CYAN}  4. Lambda Logs${NC}  → Compute > Lambda > incident-response-isolate-resource > Monitor > Logs"
echo -e "${CYAN}  5. Email SNS${NC}    → Revisar kevinlupera@gmail.com"
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  COMANDOS ÚTILES${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}  Logs Lambda en tiempo real:${NC}"
echo "  aws logs tail /aws/lambda/incident-response-isolate-resource --follow --region ${CURRENT_REGION}"
echo ""
echo -e "${YELLOW}  Ver email de alerta SNS enviado:${NC}"
echo "  aws sns list-subscriptions-by-topic \\"
echo "    --topic-arn \$(aws cloudformation describe-stacks --stack-name NotificationStack \\"
echo "      --query \"Stacks[0].Outputs[?OutputKey=='SNSTopicArn'].OutputValue\" --output text) \\"
echo "    --region ${CURRENT_REGION}"
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}${BOLD}  ✨ Nadie apretó un botón. La respuesta fue completamente automática.${NC}"
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
