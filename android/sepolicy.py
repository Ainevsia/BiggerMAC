
class SELinuxContext:
    '''selinux标签'''
    def __init__(self, user: str, role: str, ty: str, mls: str):
        self.user = user
        self.role = role
        self.type = ty
        self.mls = mls

    @staticmethod
    def FromString(context: str):   # u:r:shell:s0
        parts = context.split(":")  # [str]

        if len(parts) < 4:
            raise ValueError("Invalid SELinux label '%s'" % context)

        se_user = parts[0]
        se_role = parts[1]
        se_type = parts[2]
        # MLS is a special case and may also contain ':'
        se_mls = ":".join(parts[3:])

        return SELinuxContext(se_user, se_role, se_type, se_mls)

    def __str__(self):
        return "%s:%s:%s:%s" % (self.user, self.role, self.type, self.mls)

    def __repr__(self):
        return "<SELinuxContext %s>" % (str(self))

    def __eq__(self, rhs):
        if isinstance(rhs, SELinuxContext):
            return str(self) == str(rhs)

        return NotImplemented
