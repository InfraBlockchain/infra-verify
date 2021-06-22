"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
var did_jwt_1 = require("did-jwt");
var did_jwt_vc_1 = require("did-jwt-vc");
var did_resolver_1 = require("did-resolver");
var infra_did_resolver_1 = require("infra-did-resolver");
var infra_did_js_1 = require("infra-did-js");
var Verifier = /** @class */ (function () {
    function Verifier(config) {
        this.resolver = config.resolver ? config.resolver : new did_resolver_1.Resolver(infra_did_resolver_1.getResolver(config.networkConfig));
        this.did = config.did ? config.did : infra_did_js_1["default"].createPubKeyDIDsecp256k1('01').did;
        this.challenge = '';
        this.knownIssuers = config.knownIssuers;
    }
    Verifier.prototype.ready = function () {
        this.challenge = this.generateChallenge();
        return { challenge: this.challenge, aud: this.did };
    };
    Verifier.prototype.generateChallenge = function () {
        // use randomly generated DID as nonce for now
        return infra_did_js_1["default"].createPubKeyDIDsecp256k1('01').did;
    };
    Verifier.prototype.getVPClaims = function (vp) {
        var _this = this;
        var vcList = did_jwt_1.decodeJWT(vp).payload.vp.verifiableCredential;
        return vcList.map(function (vc) {
            return _this.getVCClaims(vc);
        }).reduce(function (result, claims) {
            return __assign(__assign({}, claims), result);
        }, {});
    };
    Verifier.prototype.getVCClaims = function (vc) {
        return did_jwt_1.decodeJWT(vc).payload.vc.credentialSubject;
    };
    Verifier.prototype.isValid = function (jwt) {
        return __awaiter(this, void 0, void 0, function () {
            var decoded;
            return __generator(this, function (_a) {
                decoded = did_jwt_1.decodeJWT(jwt);
                if (decoded.payload.vp)
                    return [2 /*return*/, this.isValidVP(jwt)];
                else if (decoded.payload.vc)
                    return [2 /*return*/, this.isValidVC(jwt)];
                else
                    throw new Error("Unsupported type");
                return [2 /*return*/];
            });
        });
    };
    Verifier.prototype.isValidVP = function (vp) {
        return __awaiter(this, void 0, void 0, function () {
            var verifiedPresentation, vcList, signer;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, did_jwt_vc_1.verifyPresentation(vp, this.resolver, { challenge: this.challenge, audience: this.did })];
                    case 1:
                        verifiedPresentation = _a.sent();
                        vcList = verifiedPresentation.payload.vp.VerifiedCredential;
                        signer = verifiedPresentation.payload.signer;
                        if (this.isRevoked(signer.did))
                            throw new Error("Deactivated Presenter");
                        return [2 /*return*/, vcList.map(function (vc) {
                                return _this.isValidVC(vc, signer.did);
                            }, this).reduce(function (result, validity) {
                                return result && validity;
                            }, true)];
                }
            });
        });
    };
    Verifier.prototype.isValidVC = function (vc, holder) {
        return __awaiter(this, void 0, void 0, function () {
            var verifiedCredential, vcID;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, did_jwt_vc_1.verifyCredential(vc, this.resolver)];
                    case 1:
                        verifiedCredential = _a.sent();
                        if (holder && verifiedCredential.payload.sub !== holder)
                            throw new Error("Signer is not the subject of VC");
                        // verify the issuer identity is valid
                        if (this.isKnownIssuer(verifiedCredential.issuer))
                            throw new Error("Unknown Issuer");
                        // verify the issuer identity has NOT been revoked
                        if (this.isRevoked(verifiedCredential.issuer))
                            throw new Error("Deactivated Issuer");
                        vcID = verifiedCredential.payload.vc.id;
                        if (this.isRevoked(vcID))
                            throw new Error("Revoked VC");
                        return [2 /*return*/, true];
                }
            });
        });
    };
    Verifier.prototype.isRevoked = function (did) {
        return __awaiter(this, void 0, void 0, function () {
            var didDoc;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.resolver.resolve(did)];
                    case 1:
                        didDoc = _a.sent();
                        if (didDoc.didDocumentMetadata.deactivated)
                            return [2 /*return*/, true];
                        return [2 /*return*/, false];
                }
            });
        });
    };
    Verifier.prototype.isKnownIssuer = function (issuer) {
        var found = this.knownIssuers.some(function (known) { return known.did === issuer; });
        if (!found)
            return false;
        return true;
    };
    return Verifier;
}());
exports["default"] = Verifier;
