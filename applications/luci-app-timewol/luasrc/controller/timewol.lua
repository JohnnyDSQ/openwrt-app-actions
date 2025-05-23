module("luci.controller.timewol", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/timewol") then return end

	entry({"admin", "control"}, firstchild(), "Control", 44).dependent = false

	local page = entry({"admin", "control", "timewol"}, cbi("timewol"), _("Timed WOL"))
	page.order = 95
	page.dependent = true
	page.acl_depends = { "luci-app-timewol" }

	entry({"admin", "control", "timewol", "status"}, call("status")).leaf = true
end

function status()
	local e = {}
	e.status = luci.sys.call("cat /etc/crontabs/root | grep -v '^[ \t]*#' | grep etherwake >/dev/null") == 0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end
