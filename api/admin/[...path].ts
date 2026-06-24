import { createHmac, createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, posix } from "node:path";

type JsonValue =
	| string
	| number
	| boolean
	| null
	| JsonValue[]
	| { [key: string]: JsonValue };

type SessionUser = {
	id: number;
	login: string;
	name?: string;
	avatar_url?: string;
};

type PostMeta = {
	title: string;
	published: string;
	updated?: string;
	draft?: boolean;
	description?: string;
	image?: string;
	tags?: string[];
	category?: string | null;
	lang?: string;
	pinned?: boolean;
	author?: string;
	sourceLink?: string;
	licenseName?: string;
	licenseUrl?: string;
	comment?: boolean;
	password?: string;
	passwordHint?: string;
};

type PostPayload = {
	slug: string;
	extension?: "md" | "mdx";
	meta: PostMeta;
	body: string;
	message?: string;
};

const defaultBranch = process.env.GITHUB_BRANCH || "main";
const repoOwner = process.env.GITHUB_REPO_OWNER || "1161616";
const repoName = process.env.GITHUB_REPO_NAME || "Firefly";

const editableConfigs: Record<string, string> = {
	siteConfig: "src/config/cms/siteConfig.json",
	announcementConfig: "src/config/cms/announcementConfig.json",
	navBarConfig: "src/config/cms/navBarConfig.json",
	friendsConfig: "src/config/cms/friendsConfig.json",
	galleryConfig: "src/config/cms/galleryConfig.json",
	musicConfig: "src/config/cms/musicConfig.json",
	backgroundWallpaper: "src/config/cms/backgroundWallpaper.json",
	commentConfig: "src/config/cms/commentConfig.json",
	analyticsConfig: "src/config/cms/analyticsConfig.json",
	sponsorConfig: "src/config/cms/sponsorConfig.json",
};

const specPages = new Set(["about", "friends", "guestbook"]);

const json = (res: ServerResponse, status: number, data: unknown) => {
	res.statusCode = status;
	res.setHeader("content-type", "application/json; charset=utf-8");
	res.end(JSON.stringify(data));
};

const redirect = (res: ServerResponse, location: string) => {
	res.statusCode = 302;
	res.setHeader("location", location);
	res.end();
};

const readBody = async (req: IncomingMessage): Promise<Buffer> => {
	const chunks: Buffer[] = [];
	for await (const chunk of req) {
		chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
	}
	return Buffer.concat(chunks);
};

const readJson = async <T>(req: IncomingMessage): Promise<T> => {
	const body = await readBody(req);
	if (!body.length) return {} as T;
	return JSON.parse(body.toString("utf-8")) as T;
};

const getOrigin = (req: IncomingMessage) => {
	const proto =
		(req.headers["x-forwarded-proto"] as string | undefined) || "http";
	return `${proto}://${req.headers.host}`;
};

const parseCookies = (req: IncomingMessage): Record<string, string> => {
	const header = req.headers.cookie || "";
	return Object.fromEntries(
		header
			.split(";")
			.map((part) => part.trim())
			.filter(Boolean)
			.map((part) => {
				const index = part.indexOf("=");
				return [
					decodeURIComponent(part.slice(0, index)),
					decodeURIComponent(part.slice(index + 1)),
				];
			}),
	);
};

const sign = (value: string) =>
	createHmac("sha256", getSessionSecret()).update(value).digest("base64url");

const getSessionSecret = () => {
	const secret = process.env.CMS_SESSION_SECRET;
	if (!secret) throw new Error("CMS_SESSION_SECRET is not configured");
	return secret;
};

const createSession = (user: SessionUser) => {
	const payload = Buffer.from(
		JSON.stringify({ user, exp: Date.now() + 1000 * 60 * 60 * 24 * 7 }),
	).toString("base64url");
	return `${payload}.${sign(payload)}`;
};

const readSession = (req: IncomingMessage): SessionUser | null => {
	const token = parseCookies(req).cms_session;
	if (!token) return null;
	const [payload, signature] = token.split(".");
	if (!payload || !signature) return null;

	const expected = sign(payload);
	const ok =
		expected.length === signature.length &&
		timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
	if (!ok) return null;

	const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf-8"));
	if (!data.exp || Date.now() > data.exp) return null;
	return data.user as SessionUser;
};

const setSessionCookie = (res: ServerResponse, user: SessionUser) => {
	res.setHeader("set-cookie", [
		`cms_session=${encodeURIComponent(createSession(user))}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${60 * 60 * 24 * 7}`,
	]);
};

const clearSessionCookie = (res: ServerResponse) => {
	res.setHeader("set-cookie", [
		"cms_session=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0",
	]);
};

const getAllowedUsers = () =>
	new Set(
		(process.env.CMS_ALLOWED_USERS || "")
			.split(",")
			.map((user) => user.trim().toLowerCase())
			.filter(Boolean),
	);

const ensureUser = (req: IncomingMessage): SessionUser => {
	const user = readSession(req);
	if (!user) {
		const error = new Error("Unauthorized");
		(error as Error & { status?: number }).status = 401;
		throw error;
	}

	const allowed = getAllowedUsers();
	if (allowed.size && !allowed.has(user.login.toLowerCase())) {
		const error = new Error("Forbidden");
		(error as Error & { status?: number }).status = 403;
		throw error;
	}

	return user;
};

const githubFetch = async <T>(
	path: string,
	options: RequestInit = {},
): Promise<T> => {
	const token = process.env.GITHUB_WRITE_TOKEN;
	if (!token) throw new Error("GITHUB_WRITE_TOKEN is not configured");

	const response = await fetch(`https://api.github.com${path}`, {
		...options,
		headers: {
			accept: "application/vnd.github+json",
			authorization: `Bearer ${token}`,
			"user-agent": "firefly-cms",
			"x-github-api-version": "2022-11-28",
			...options.headers,
		},
	});

	if (!response.ok) {
		const text = await response.text();
		throw new Error(`GitHub API ${response.status}: ${text}`);
	}

	return (await response.json()) as T;
};

const contentPath = (path: string) =>
	`/repos/${repoOwner}/${repoName}/contents/${encodeURIComponent(path).replace(
		/%2F/g,
		"/",
	)}`;

const getGithubFile = async (
	path: string,
): Promise<{ content: string; sha: string } | null> => {
	try {
		const data = await githubFetch<{
			content: string;
			encoding: string;
			sha: string;
		}>(`${contentPath(path)}?ref=${encodeURIComponent(defaultBranch)}`);
		const content = Buffer.from(data.content, "base64").toString("utf-8");
		return { content, sha: data.sha };
	} catch (error) {
		if (error instanceof Error && error.message.includes("GitHub API 404")) {
			return null;
		}
		throw error;
	}
};

const putGithubFile = async (
	path: string,
	content: string | Buffer,
	message: string,
) => {
	const current = await getGithubFile(path);
	const payload: Record<string, unknown> = {
		message,
		branch: defaultBranch,
		content: Buffer.from(content).toString("base64"),
	};
	if (current?.sha) payload.sha = current.sha;

	return githubFetch<{ commit: { sha: string; html_url: string } }>(
		contentPath(path),
		{
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(payload),
		},
	);
};

const deleteGithubFile = async (path: string, message: string) => {
	const current = await getGithubFile(path);
	if (!current) return null;
	return githubFetch<{ commit: { sha: string; html_url: string } }>(
		contentPath(path),
		{
			method: "DELETE",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				message,
				branch: defaultBranch,
				sha: current.sha,
			}),
		},
	);
};

const listGithubDir = async (path: string) => {
	try {
		return await githubFetch<Array<{ name: string; path: string; type: string }>>(
			`${contentPath(path)}?ref=${encodeURIComponent(defaultBranch)}`,
		);
	} catch (error) {
		if (error instanceof Error && error.message.includes("GitHub API 404")) {
			return [];
		}
		throw error;
	}
};

const flattenDir = async (path: string): Promise<Array<{ path: string }>> => {
	const entries = await listGithubDir(path);
	const files = await Promise.all(
		entries.map(async (entry) =>
			entry.type === "dir" ? flattenDir(entry.path) : [{ path: entry.path }],
		),
	);
	return files.flat();
};

const parseFrontmatter = (source: string): { meta: Record<string, unknown>; body: string } => {
	if (!source.startsWith("---")) return { meta: {}, body: source };
	const end = source.indexOf("\n---", 3);
	if (end === -1) return { meta: {}, body: source };
	const raw = source.slice(3, end).trim();
	const body = source.slice(end + 4).replace(/^\r?\n/, "");
	return { meta: parseSimpleYaml(raw), body };
};

const parseSimpleYaml = (raw: string): Record<string, unknown> => {
	const result: Record<string, unknown> = {};
	for (const line of raw.split(/\r?\n/)) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#")) continue;
		const index = trimmed.indexOf(":");
		if (index === -1) continue;
		const key = trimmed.slice(0, index).trim();
		const value = trimmed.slice(index + 1).trim();
		result[key] = parseYamlValue(value);
	}
	return result;
};

const parseYamlValue = (value: string): unknown => {
	if (!value) return "";
	if (value === "true") return true;
	if (value === "false") return false;
	if (value === "null") return null;
	if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
	if (value.startsWith("[") && value.endsWith("]")) {
		return value
			.slice(1, -1)
			.split(",")
			.map((item) => stripQuotes(item.trim()))
			.filter(Boolean);
	}
	return stripQuotes(value);
};

const stripQuotes = (value: string) => {
	if (
		(value.startsWith('"') && value.endsWith('"')) ||
		(value.startsWith("'") && value.endsWith("'"))
	) {
		return value.slice(1, -1);
	}
	return value;
};

const formatMarkdown = (meta: PostMeta, body: string) =>
	`---\n${Object.entries(meta)
		.filter(([, value]) => value !== undefined && value !== null && value !== "")
		.map(([key, value]) => `${key}: ${formatYamlValue(value)}`)
		.join("\n")}\n---\n\n${body.trimStart()}`;

const formatYamlValue = (value: unknown): string => {
	if (Array.isArray(value)) {
		return `[${value.map((item) => JSON.stringify(item)).join(", ")}]`;
	}
	if (typeof value === "boolean" || typeof value === "number") return String(value);
	return JSON.stringify(value ?? "");
};

const safeSlug = (slug: string) => {
	const normalized = slug.replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
	if (
		!normalized ||
		normalized.includes("..") ||
		!/^[-\w./\u4e00-\u9fa5]+$/.test(normalized)
	) {
		throw new Error("Invalid slug");
	}
	return normalized.replace(/\.(md|mdx)$/i, "");
};

const postPath = (slug: string, extension = "md") =>
	`src/content/posts/${safeSlug(slug)}.${extension === "mdx" ? "mdx" : "md"}`;

const specPath = (page: string) => {
	if (!specPages.has(page)) throw new Error("Unknown spec page");
	return `src/content/spec/${page === "friends" ? "friends.mdx" : `${page}.md`}`;
};

const handleMe = (req: IncomingMessage, res: ServerResponse) => {
	const user = readSession(req);
	const allowed = getAllowedUsers();
	json(res, 200, {
		authenticated: !!user,
		allowed: !!user && (!allowed.size || allowed.has(user.login.toLowerCase())),
		user,
		repository: `${repoOwner}/${repoName}`,
		branch: defaultBranch,
		configKeys: Object.keys(editableConfigs),
	});
};

const handleLogin = (req: IncomingMessage, res: ServerResponse) => {
	const clientId = process.env.GITHUB_CLIENT_ID;
	if (!clientId) throw new Error("GITHUB_CLIENT_ID is not configured");
	const state = randomBytes(16).toString("hex");
	res.setHeader(
		"set-cookie",
		`cms_oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=600`,
	);
	const redirectUri = `${getOrigin(req)}/api/admin/auth/callback`;
	redirect(
		res,
		`https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(
			clientId,
		)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=read:user&state=${state}`,
	);
};

const handleCallback = async (
	req: IncomingMessage,
	res: ServerResponse,
	url: URL,
) => {
	const code = url.searchParams.get("code");
	const state = url.searchParams.get("state");
	const cookies = parseCookies(req);
	if (!code || !state || state !== cookies.cms_oauth_state) {
		redirect(res, "/admin?error=oauth_state");
		return;
	}

	const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
		method: "POST",
		headers: {
			accept: "application/json",
			"content-type": "application/json",
		},
		body: JSON.stringify({
			client_id: process.env.GITHUB_CLIENT_ID,
			client_secret: process.env.GITHUB_CLIENT_SECRET,
			code,
			redirect_uri: `${getOrigin(req)}/api/admin/auth/callback`,
		}),
	});
	const tokenData = (await tokenResponse.json()) as { access_token?: string };
	if (!tokenData.access_token) {
		redirect(res, "/admin?error=oauth_token");
		return;
	}

	const userResponse = await fetch("https://api.github.com/user", {
		headers: {
			accept: "application/vnd.github+json",
			authorization: `Bearer ${tokenData.access_token}`,
			"user-agent": "firefly-cms",
		},
	});
	const user = (await userResponse.json()) as SessionUser;
	const allowed = getAllowedUsers();
	if (allowed.size && !allowed.has(user.login.toLowerCase())) {
		redirect(res, "/admin?error=forbidden");
		return;
	}

	setSessionCookie(res, user);
	redirect(res, "/admin");
};

const handlePosts = async (
	req: IncomingMessage,
	res: ServerResponse,
	parts: string[],
) => {
	ensureUser(req);

	if (req.method === "GET" && parts.length === 0) {
		const files = (await flattenDir("src/content/posts")).filter((file) =>
			/\.(md|mdx)$/i.test(file.path),
		);
		const posts = await Promise.all(
			files.map(async (file) => {
				const content = await getGithubFile(file.path);
				const parsed = parseFrontmatter(content?.content || "");
				const slug = file.path
					.replace(/^src\/content\/posts\//, "")
					.replace(/\.(md|mdx)$/i, "");
				return {
					slug,
					path: file.path,
					extension: extname(file.path).slice(1),
					meta: parsed.meta,
					body: parsed.body,
				};
			}),
		);
		json(res, 200, { posts });
		return;
	}

	if (req.method === "GET" && parts.length > 0) {
		const slug = parts.join("/");
		const md = await getGithubFile(postPath(slug, "md"));
		const mdx = md ? null : await getGithubFile(postPath(slug, "mdx"));
		const file = md || mdx;
		if (!file) {
			json(res, 404, { error: "Post not found" });
			return;
		}
		const parsed = parseFrontmatter(file.content);
		json(res, 200, {
			slug: safeSlug(slug),
			extension: md ? "md" : "mdx",
			meta: parsed.meta,
			body: parsed.body,
		});
		return;
	}

	if (req.method === "POST" || req.method === "PUT") {
		const payload = await readJson<PostPayload>(req);
		const slug = safeSlug(parts.join("/") || payload.slug);
		const extension = payload.extension === "mdx" ? "mdx" : "md";
		const path = postPath(slug, extension);
		const data = formatMarkdown(payload.meta, payload.body || "");
		const commit = await putGithubFile(
			path,
			data,
			payload.message || `cms: update post ${slug}`,
		);
		json(res, 200, { ok: true, path, commit: commit.commit });
		return;
	}

	if (req.method === "DELETE" && parts.length > 0) {
		const slug = safeSlug(parts.join("/"));
		const md = await getGithubFile(postPath(slug, "md"));
		const extension = md ? "md" : "mdx";
		const commit = await deleteGithubFile(
			postPath(slug, extension),
			`cms: delete post ${slug}`,
		);
		json(res, 200, { ok: true, commit: commit?.commit || null });
		return;
	}

	json(res, 405, { error: "Method not allowed" });
};

const handleSpec = async (
	req: IncomingMessage,
	res: ServerResponse,
	parts: string[],
) => {
	ensureUser(req);
	const page = parts[0];
	if (!page) {
		json(res, 200, { pages: Array.from(specPages) });
		return;
	}
	const path = specPath(page);
	if (req.method === "GET") {
		const file = await getGithubFile(path);
		json(res, 200, { page, path, content: file?.content || "" });
		return;
	}
	if (req.method === "PUT") {
		const payload = await readJson<{ content: string; message?: string }>(req);
		const commit = await putGithubFile(
			path,
			payload.content || "",
			payload.message || `cms: update spec ${page}`,
		);
		json(res, 200, { ok: true, path, commit: commit.commit });
		return;
	}
	json(res, 405, { error: "Method not allowed" });
};

const handleConfig = async (
	req: IncomingMessage,
	res: ServerResponse,
	parts: string[],
) => {
	ensureUser(req);
	const key = parts[0];
	if (!key) {
		json(res, 200, {
			configs: Object.entries(editableConfigs).map(([name, path]) => ({
				name,
				path,
			})),
		});
		return;
	}
	const path = editableConfigs[key];
	if (!path) {
		json(res, 404, { error: "Unknown config key" });
		return;
	}
	if (req.method === "GET") {
		const file = await getGithubFile(path);
		json(res, 200, {
			key,
			path,
			value: file?.content ? JSON.parse(file.content) : {},
		});
		return;
	}
	if (req.method === "PUT") {
		const payload = await readJson<{ value: JsonValue; message?: string }>(req);
		const content = `${JSON.stringify(payload.value ?? {}, null, 2)}\n`;
		const commit = await putGithubFile(
			path,
			content,
			payload.message || `cms: update config ${key}`,
		);
		json(res, 200, { ok: true, path, commit: commit.commit });
		return;
	}
	json(res, 405, { error: "Method not allowed" });
};

const getAssetName = (name: string) => {
	const base = name.replace(/\\/g, "/").split("/").pop() || "asset";
	const safe = base.replace(/[^\w.\-\u4e00-\u9fa5]/g, "-");
	return `${Date.now()}-${safe}`;
};

const handleAssets = async (req: IncomingMessage, res: ServerResponse) => {
	ensureUser(req);
	if (req.method !== "POST") {
		json(res, 405, { error: "Method not allowed" });
		return;
	}
	const payload = await readJson<{
		target: "github" | "r2";
		name: string;
		contentType?: string;
		data: string;
		directory?: string;
	}>(req);
	const data = Buffer.from(
		payload.data.includes(",") ? payload.data.split(",").pop() || "" : payload.data,
		"base64",
	);
	const fileName = getAssetName(payload.name);

	if (payload.target === "r2") {
		const key = posix.join(payload.directory || "firefly-cms", fileName);
		await putR2Object(key, data, payload.contentType || "application/octet-stream");
		const baseUrl = process.env.R2_PUBLIC_BASE_URL;
		if (!baseUrl) throw new Error("R2_PUBLIC_BASE_URL is not configured");
		json(res, 200, { ok: true, target: "r2", key, url: `${baseUrl.replace(/\/$/, "")}/${key}` });
		return;
	}

	const directory = payload.directory || "public/assets/cms";
	const path = posix.join(directory, fileName);
	const commit = await putGithubFile(path, data, `cms: upload asset ${fileName}`);
	json(res, 200, {
		ok: true,
		target: "github",
		path,
		url: `/${path.replace(/^public\//, "")}`,
		commit: commit.commit,
	});
};

const hmac = (key: Buffer | string, value: string) =>
	createHmac("sha256", key).update(value).digest();

const hexHash = (value: Buffer | string) =>
	createHash("sha256").update(value).digest("hex");

const putR2Object = async (key: string, body: Buffer, contentType: string) => {
	const accountId = process.env.R2_ACCOUNT_ID;
	const accessKeyId = process.env.R2_ACCESS_KEY_ID;
	const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
	const bucket = process.env.R2_BUCKET;
	if (!accountId || !accessKeyId || !secretAccessKey || !bucket) {
		throw new Error("R2 environment variables are not fully configured");
	}

	const now = new Date();
	const dateStamp = now.toISOString().slice(0, 10).replace(/-/g, "");
	const amzDate = `${dateStamp}T${now.toISOString().slice(11, 19).replace(/:/g, "")}Z`;
	const host = `${accountId}.r2.cloudflarestorage.com`;
	const pathname = `/${bucket}/${key.split("/").map(encodeURIComponent).join("/")}`;
	const payloadHash = hexHash(body);
	const signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
	const canonicalRequest = [
		"PUT",
		pathname,
		"",
		`content-type:${contentType}`,
		`host:${host}`,
		`x-amz-content-sha256:${payloadHash}`,
		`x-amz-date:${amzDate}`,
		"",
		signedHeaders,
		payloadHash,
	].join("\n");
	const scope = `${dateStamp}/auto/s3/aws4_request`;
	const stringToSign = [
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hexHash(canonicalRequest),
	].join("\n");
	const dateKey = hmac(`AWS4${secretAccessKey}`, dateStamp);
	const regionKey = hmac(dateKey, "auto");
	const serviceKey = hmac(regionKey, "s3");
	const signingKey = hmac(serviceKey, "aws4_request");
	const signature = createHmac("sha256", signingKey)
		.update(stringToSign)
		.digest("hex");
	const authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

	const response = await fetch(`https://${host}${pathname}`, {
		method: "PUT",
		headers: {
			authorization,
			"content-type": contentType,
			"x-amz-content-sha256": payloadHash,
			"x-amz-date": amzDate,
		},
		body: body.buffer.slice(
			body.byteOffset,
			body.byteOffset + body.byteLength,
		) as BodyInit,
	});
	if (!response.ok) {
		throw new Error(`R2 upload failed ${response.status}: ${await response.text()}`);
	}
};

const handlePublish = async (req: IncomingMessage, res: ServerResponse) => {
	ensureUser(req);
	if (req.method !== "POST") {
		json(res, 405, { error: "Method not allowed" });
		return;
	}
	json(res, 200, {
		ok: true,
		message:
			"Changes are committed immediately by each save operation. Vercel should rebuild from the main branch commit.",
	});
};

export default async function handler(req: IncomingMessage, res: ServerResponse) {
	try {
		const url = new URL(req.url || "/", getOrigin(req));
		const parts = url.pathname
			.replace(/^\/api\/admin\/?/, "")
			.split("/")
			.filter(Boolean)
			.map(decodeURIComponent);
		const [section, ...rest] = parts;

		if (!section || section === "me") return handleMe(req, res);
		if (section === "auth" && rest[0] === "login") return handleLogin(req, res);
		if (section === "auth" && rest[0] === "logout") {
			clearSessionCookie(res);
			return redirect(res, "/admin");
		}
		if (section === "auth" && rest[0] === "callback") {
			return await handleCallback(req, res, url);
		}
		if (section === "content" && rest[0] === "posts") {
			return await handlePosts(req, res, rest.slice(1));
		}
		if (section === "content" && rest[0] === "spec") {
			return await handleSpec(req, res, rest.slice(1));
		}
		if (section === "config") return await handleConfig(req, res, rest);
		if (section === "assets") return await handleAssets(req, res);
		if (section === "publish") return await handlePublish(req, res);

		json(res, 404, { error: "Not found" });
	} catch (error) {
		const status = (error as Error & { status?: number }).status || 500;
		json(res, status, {
			error: error instanceof Error ? error.message : "Unknown error",
		});
	}
}
