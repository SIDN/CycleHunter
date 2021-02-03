
def getparent(domain):
    z = domain
    if domain[-1] != ".":
        z = domain + "."
    sp = z.split(".")
    parent = ''

    if len(sp) > 3:
        for k in range(1, len(sp) - 1):
            # print(k)
            parent = parent + "." + sp[k]
    elif len(sp) == 3:
        parent = sp[-2]
        return parent
    elif len(sp) == 2:
        parent = domain + "."
        return parent

    try:
        if parent[0] == ".":
            parent = parent[1:]
    except:
        print("stop here at getParent")

    return parent

