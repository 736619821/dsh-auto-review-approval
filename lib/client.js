window.__ModuleLoader__.load({
	id: "dsh-smart-approval",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
		let react = require("react");
		let react_jsx_runtime = require("react/jsx-runtime");
		// src/client/ReviewModeSelect.tsx
		const triggerStyle = {
			display: "inline-flex",
			alignItems: "center",
			gap: 4,
			minWidth: 0,
			maxWidth: 180,
			height: 28,
			padding: "0 22px 0 8px",
			border: "none",
			borderRadius: 24,
			outline: "none",
			background: "transparent",
			color: "var(--dsw-alias-label-secondary)",
			fontSize: 13,
			lineHeight: "20px",
			fontWeight: 500,
			cursor: "pointer",
			appearance: "none"
		};
		/** Localized label key for one closed review mode. */
		function modeKey(mode) {
			return `mode.${mode}`;
		}
		/** Independent automatic-review selector shown beside the access control. */
		function ReviewModeSelect({ useProjection, select, t }) {
			const projection = useProjection("approvalReview");
			const [busy, setBusy] = (0, react.useState)(false);
			const [failed, setFailed] = (0, react.useState)(false);
			if (projection === void 0) return null;
			const current = projection.mode;
			const currentLabel = t(modeKey(current));
			const choose = (mode) => {
				if (mode === current) return;
				setBusy(true);
				setFailed(false);
				select(mode).then((accepted) => {
					setBusy(false);
					setFailed(!accepted);
				}, () => {
					setBusy(false);
					setFailed(true);
				});
			};
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("span", {
				style: {
					display: "inline-flex",
					alignItems: "center",
					position: "relative"
				},
				children: [
					/* @__PURE__ */ (0, react_jsx_runtime.jsx)("select", {
						style: triggerStyle,
						"aria-label": t("trigger.aria", { mode: currentLabel }),
						title: t("trigger.title", { mode: currentLabel }),
						value: current,
						disabled: busy,
						onChange: (event) => {
							choose(event.currentTarget.value);
						},
						children: [
							"manual",
							"smart",
							"unattended"
						].map((mode) => /* @__PURE__ */ (0, react_jsx_runtime.jsx)("option", {
							value: mode,
							children: t(modeKey(mode))
						}, mode))
					}),
					/* @__PURE__ */ (0, react_jsx_runtime.jsx)("svg", {
						width: "14",
						height: "14",
						viewBox: "0 0 14 14",
						fill: "none",
						"aria-hidden": true,
						style: {
							position: "absolute",
							right: 4,
							pointerEvents: "none",
							color: "var(--dsw-alias-label-caption)"
						},
						children: /* @__PURE__ */ (0, react_jsx_runtime.jsx)("path", {
							d: "M3.5 5.25L7 8.75L10.5 5.25",
							stroke: "currentColor",
							strokeWidth: "1.2",
							strokeLinecap: "round",
							strokeLinejoin: "round"
						})
					}),
					failed && /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
						role: "status",
						title: t("error.switch"),
						style: {
							color: "var(--dsw-alias-label-error)",
							fontSize: 12
						},
						children: t("error.switch")
					})
				]
			});
		}
		// src/client/locales.ts
		/** Simplified Chinese copy for the independent automatic-review selector. */
		const zh = {
			"trigger.aria": "自动审查，当前：{mode}",
			"trigger.title": "自动审查模式：{mode}",
			"mode.manual": "人工审批",
			"mode.smart": "智能审批",
			"mode.unattended": "无人值守",
			"error.switch": "切换自动审查模式失败"
		};
		/** English copy checked against the Chinese key set. */
		const en = {
			"trigger.aria": "Automatic review, current: {mode}",
			"trigger.title": "Automatic review mode: {mode}",
			"mode.manual": "Manual approval",
			"mode.smart": "Smart approval",
			"mode.unattended": "Unattended",
			"error.switch": "Failed to switch automatic review mode"
		};
		// src/client/index.ts
		/** Browser services required by the composer contribution. */
		const inject = [
			"slots",
			"remote",
			"remote.commands",
			"locale"
		];
		/** Register the independent selector beside the access-mode control. */
		function apply(ctx) {
			ctx.effect(() => ctx.locale.register("approval-review", {
				zh,
				en
			}), "smart-approval: browser dictionaries");
			ctx.slots.inject("conversation.input.left", () => ctx.slots.register({
				name: "conversation.input.left",
				id: "approval-review",
				order: -10,
				locale: "approval-review",
				inject: (sessionId) => ({ select: async (mode) => {
					const result = await ctx.remote.commands.execute(sessionId, `/approval-mode ${mode}`, []);
					return result.ok && result.value !== void 0 && result.value.result.kind === "success";
				} })
			}, ReviewModeSelect));
		}
		exports.ReviewModeSelect = ReviewModeSelect;
		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});

//# sourceMappingURL=client.js.map