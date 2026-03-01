export interface WalkShellAstHandlers {
	shouldStop?: () => boolean;
	onCommand?: (node: any) => void;
	onFunction?: (node: any) => void;
	onUnknown?: (type: string | undefined, node: any) => void;
}

export function walkShellAst(node: any, handlers: WalkShellAstHandlers): void {
	const walk = (current: any): void => {
		if (handlers.shouldStop?.()) return;
		if (!current) return;
		if (Array.isArray(current)) {
			for (const item of current) walk(item);
			return;
		}
		if (typeof current !== "object") return;

		const type = current.type as string | undefined;
		if (!type) {
			handlers.onUnknown?.(type, current);
			return;
		}

		switch (type) {
			case "Script":
				walk(current.commands);
				return;
			case "LogicalExpression":
				walk(current.left);
				walk(current.right);
				return;
			case "Pipeline":
				walk(current.commands);
				return;
			case "Command":
				handlers.onCommand?.(current);
				walk(current.prefix);
				walk(current.suffix);
				return;
			case "CompoundList":
				walk(current.commands);
				walk(current.redirections);
				return;
			case "Subshell":
				walk(current.list);
				return;
			case "Case":
				walk(current.clause);
				walk(current.cases);
				return;
			case "CaseItem":
				walk(current.pattern);
				walk(current.body);
				return;
			case "If":
				walk(current.clause);
				walk(current.then);
				walk(current.else);
				return;
			case "For":
				walk(current.wordlist);
				walk(current.do);
				return;
			case "While":
			case "Until":
				walk(current.clause);
				walk(current.do);
				return;
			case "Function":
				handlers.onFunction?.(current);
				return;
			case "Word":
			case "AssignmentWord":
				walk(current.expansion);
				return;
			case "CommandExpansion":
				walk(current.commandAST);
				return;
			case "Redirect":
				walk(current.file);
				return;
			case "ArithmeticExpansion":
			case "ParameterExpansion":
			case "Name":
				return;
			default:
				handlers.onUnknown?.(type, current);
				return;
		}
	};

	walk(node);
}
