

def hello(name="FESB"):
    print(f"Hello,{name}");

def say(**args):
    what=args.get("what","hello");
    name=args.get("name","nobody");
    print(f"{what},{name}");

hello(__name__)

if __name__=='__main__':
    hello()

DEFAULT_NAME="FESB"