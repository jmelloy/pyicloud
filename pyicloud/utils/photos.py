from pyicloud.utils.bplist import BPListReader
import base64


def parse_fields(fields: dict, keypath="") -> dict:

    parsed = {}
    for key, value in fields.items():
        print(f"{keypath}.{key}", type(value), str(value)[:20])
        val = value

        if type(value) == dict:
            val = value.get("value", value)

        if key.endswith("Enc"):
            try:
                val = BPListReader(base64.b64decode(val)).parse()
            except BPListReader.BadMagicException as e:
                val = base64.b64decode(val)
            key = key.replace("Enc", "")

        if type(val) == dict:
            val = parse_fields(val, keypath=f"{keypath}.{key}")

        if type(val) == tuple and len(val) == 2:
            val = val[1]

        if type(val) == bytes:
            try:
                val = val.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    val = val.decode("utf-16")
                except UnicodeDecodeError:
                    pass

        parsed[key] = val

    return parsed
