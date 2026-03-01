export type PermissionDomain = "ssh" | "bash";

export interface PolicyGrant {
	fingerprint: string;
	target: string;
	commandPreview: string;
	createdAt: string;
	domain: PermissionDomain;
}

export interface PermissionsConfig {
	ssh?: { enabled: boolean };
	bash?: { enabled: boolean };
}

export interface PolicyFile {
	version: 1 | 2;
	updatedAt: string;
	grants: PolicyGrant[];
	permissions?: PermissionsConfig;
}

export interface TrustedProject {
	projectId: string;
	projectRootRealpath: string;
	createdAt: string;
}

export interface TrustFile {
	version: 1;
	updatedAt: string;
	trustedProjects: TrustedProject[];
}

export interface EffectivePolicy {
	global: PolicyFile;
	project: PolicyFile;
	trustedProject: boolean;
	effectiveFingerprints: Set<string>;
}

export function emptyPolicyFile(): PolicyFile {
	return { version: 2, updatedAt: new Date().toISOString(), grants: [] };
}

export function emptyTrustFile(): TrustFile {
	return { version: 1, updatedAt: new Date().toISOString(), trustedProjects: [] };
}
