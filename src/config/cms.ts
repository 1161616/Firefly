type PlainObject = Record<string, unknown>;

const isPlainObject = (value: unknown): value is PlainObject =>
	typeof value === "object" && value !== null && !Array.isArray(value);

export const mergeCmsConfig = <T>(base: T, override: unknown): T => {
	if (!isPlainObject(base) || !isPlainObject(override)) return base;

	const result: PlainObject = { ...base };

	for (const [key, value] of Object.entries(override)) {
		if (value === undefined || value === null) continue;

		const current = result[key];
		result[key] =
			isPlainObject(current) && isPlainObject(value)
				? mergeCmsConfig(current, value)
				: value;
	}

	return result as T;
};

export const useCmsValue = <T>(base: T, override: unknown): T =>
	override === undefined || override === null ? base : (override as T);
