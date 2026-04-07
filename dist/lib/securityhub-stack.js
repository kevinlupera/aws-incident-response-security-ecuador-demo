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
exports.SecurityHubStack = void 0;
const cdk = __importStar(require("aws-cdk-lib"));
const securityhub = __importStar(require("aws-cdk-lib/aws-securityhub"));
/**
 * Stack de AWS Security Hub.
 *
 * Security Hub actúa como el SIEM nativo de AWS:
 *   - Agrega hallazgos de GuardDuty, Inspector, Macie, Firewall Manager, etc.
 *   - Normaliza todos los hallazgos al formato ASFF (Amazon Security Finding Format)
 *   - Evalúa controles de seguridad contra estándares como FSBP y CIS
 *
 * IMPORTANTE: Este stack tiene addDependency(GuardDutyStack) en app.ts
 *             para garantizar que GuardDuty exista antes de que Security Hub
 *             intente recibir sus hallazgos.
 *
 * enableDefaultStandards: true activa automáticamente:
 *   - AWS Foundational Security Best Practices (FSBP) v1.0.0 → 300+ controles
 *   - CIS AWS Foundations Benchmark v1.2.0
 */
class SecurityHubStack extends cdk.Stack {
    constructor(scope, id, props) {
        super(scope, id, props);
        // Habilitar Security Hub con los estándares por defecto de AWS.
        //
        // enableDefaultStandards: true  → habilita FSBP + CIS automáticamente.
        //   ⚠️  enableDefaultStandards: false puede dejar Security Hub en estado
        //       "no configurado" en la consola, aunque el recurso exista en CF.
        //
        // autoEnableControls: true → los nuevos controles que AWS publique
        //   en estándares activos se habilitan automáticamente.
        new securityhub.CfnHub(this, 'SecurityHub', {
            enableDefaultStandards: true,
            autoEnableControls: true,
        });
    }
}
exports.SecurityHubStack = SecurityHubStack;
