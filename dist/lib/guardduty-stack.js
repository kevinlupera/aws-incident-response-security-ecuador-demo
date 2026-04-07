"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.GuardDutyStack = void 0;
const cdk = __importStar(require("aws-cdk-lib"));
const guardduty = __importStar(require("aws-cdk-lib/aws-guardduty"));
const config_1 = require("./config");
/**
 * Stack que habilita Amazon GuardDuty con protecciones adicionales.
 *
 * GuardDuty analiza continuamente:
 *   - AWS CloudTrail Events (API calls sospechosos)
 *   - VPC Flow Logs (tráfico de red anómalo)
 *   - DNS Logs (comunicación con dominios maliciosos)
 *   - S3 Data Events (accesos indebidos a buckets)
 *   - EKS Audit Logs (actividad maliciosa en Kubernetes)
 *
 * Exporta el DetectorId para uso en scripts de simulación.
 */
class GuardDutyStack extends cdk.Stack {
    constructor(scope, id, props) {
        super(scope, id, props);
        // Construir lista de features habilitados según configuración
        const features = [];
        if (config_1.config.featureFlags.enableS3Protection) {
            features.push({
                name: 'S3_DATA_EVENTS',
                status: 'ENABLED',
            });
        }
        if (config_1.config.featureFlags.enableEKSProtection) {
            features.push({
                name: 'EKS_AUDIT_LOGS',
                status: 'ENABLED',
            });
        }
        if (config_1.config.featureFlags.enableMalwareProtection) {
            features.push({
                name: 'EBS_MALWARE_PROTECTION',
                status: 'ENABLED',
            });
        }
        // Crear el detector de GuardDuty
        // findingPublishingFrequency controla cada cuánto se envían los hallazgos
        // a EventBridge (FIFTEEN_MINUTES para demos, SIX_HOURS para producción)
        const detector = new guardduty.CfnDetector(this, 'GuardDutyDetector', {
            enable: true,
            findingPublishingFrequency: config_1.config.featureFlags.findingPublishingFrequency,
            features,
        });
        this.detectorId = detector.ref;
        // Exportar el ID del detector — lo usará simulate.sh automáticamente
        new cdk.CfnOutput(this, 'DetectorId', {
            value: this.detectorId,
            description: 'ID del detector de GuardDuty',
            exportName: 'GuardDutyDetectorId',
        });
    }
}
exports.GuardDutyStack = GuardDutyStack;
