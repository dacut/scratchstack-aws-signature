#!/usr/bin/env python3
"""\
Usage: coverage_fixup.py [options] <filename>
Remove extraneous bits from an lcov file.

Options:
    -h | --help
        Show this usage information
"""
from os import rename
from getopt import getopt, GetoptError
import string
import sys

def main(args):
    try:
        opts, args = getopt(args, 'h', ['help'])
    except GetoptError as err:
        usage()
        return 2
    
    for opt, val in opts:
        if opt in ['-h', '--help']:
            usage(sys.stdout)
            return 0
    
    if not args:
        print("Missing filename", file=sys.stderr)
        usage()
        return 2
    
    if len(args) > 1:
        print(f"Unknown argument {args[1]}", file=sys.stderr)
        usage()
        return 2

    current_sourcefile = None
    with open(args[0], "r") as ifd:
        with open(args[0] + ".fixed", "w") as ofd:
            line = ifd.readline()
            ofd.write(line)
            for line in ifd:
                line = line
                if line.startswith("SF:"):
                    current_sourcefile = line[3:].strip()
                elif line == "end_of_record\n":
                    if is_valid_sourcefile(current_sourcefile):
                        ofd.write(line)
                    current_sourcefile = None
                    continue

                if line.startswith("FN:") or line.startswith("FNDA:"):
                    parts = line.split(",")
                    function_name = parts[1].strip()
                    if function_name.startswith("_R"):
                        function_name = demangle(function_name)

                    # Don't write Rust type generics
                    if function_name.endswith("::<_>"):
                        continue
                    line = f"{parts[0]},{function_name}\n"

                if is_valid_sourcefile(current_sourcefile):
                    ofd.write(line)

    rename(args[0] + ".fixed", args[0])

    return 0

def is_valid_sourcefile(filename):
    if filename is None:
        return True
    return not filename.startswith("/rustc") and "/.cargo/registry" not in filename

def usage(fd=sys.stderr):
    fd.write(__doc__)

## RustDemangler

## main.py
def demangle(inp_str: str):
    robj = RustDemangler()
    return robj.demangle(inp_str)

## rust.py
class TypeNotFoundError(Exception):
    def __init__(self, given_str, message="Not able to detect the Type for the given string"):
        self.message = message
        self.given_str = given_str
        super().__init__(self.message)
    
    def __str__(self):
        return f'[{self.given_str}] {self.message}'

class RustDemangler(object):
    LEGACYTYPE = 0
    V0TYPE = 1

    def __init__(self):
        self.legacy = LegacyDemangler()
        self.v0 = V0Demangler()

    def demangle(self, inpstr: str) -> str:
        """ Demangle the given string

        Args:
            inpstr (str): String to be demangled
        """
        curr_type = self.determine_type(inpstr)
        if curr_type == self.LEGACYTYPE:
            return self.legacy.demangle(inpstr)
        else:
            return self.v0.demangle(inpstr)


    def determine_type(self, inpstr: str) -> int:
        """ Determine the type of the given string

        Args:
            inpstr (str): Input String

        Raises:
            TypeNotFoundError: If the string can't be determined

        Returns:
            int: type of the string
        """ 
        if inpstr.startswith("_ZN") or inpstr.startswith("ZN") or inpstr.startswith("__ZN"):
            return self.LEGACYTYPE
        elif inpstr.startswith("_R") or inpstr.startswith("R") or inpstr.startswith("__R"):
            return self.V0TYPE
        else:
            raise TypeNotFoundError(inpstr)

## rust_legacy.py

class UnableToLegacyDemangle(Exception):
    def __init__(self, given_str, message="Not able to demangle the given string using LegacyDemangler"):
        self.message = message
        self.given_str = given_str
        super().__init__(self.message)
    
    def __str__(self):
        return f'[{self.given_str}] {self.message}'

class LegacyDemangler(object):

    def demangle(self, inpstr : str) -> str:
        self.elements = 0

        disp = ""
        inpstr = inpstr[inpstr.index("N") + 1:]
        self.sanity_check(inpstr)

        if ".llvm." in inpstr:
            l = inpstr.find(".llvm.")
            candidate = inpstr[l+6:]
            for i in candidate: 
                if i not in string.hexdigits + "@":
                    raise UnableToLegacyDemangle(inpstr) 
            inpstr = inpstr[:l]   

        inn = inpstr
        for ele in range(self.elements):
            
            rest = inn
            for i in rest:
                if i.isdigit():
                    rest = rest[1:]
                    continue
                else:
                    break    
            
            num = int(inn[0:len(inn)-len(rest)]) 

            inn = rest[num:]   
            rest = rest[:num]   

            if ele != 0:
                disp += "::"

            if ele + 1 == self.elements:  
                if self.is_rust_hash(rest):
                    disp += rest
                    break
            
            if rest.startswith("_$"):
                rest = rest[1:]

            while True:
                if rest.startswith("."):
                    if rest[1:].startswith("."):  
                        disp += "::"
                        rest = rest[2:]
                    else:
                        disp += "."
                        rest = rest[1:]

                elif rest.startswith("$"):
                    end = rest[1:].find("$")
                    escape = rest[1:end+1]
                    after_escape = rest[end+2:] 
                
                    unescaped ={'SP': '@' , 'BP': '*' , 'RF': '&' , 'LT': '<' , 'GT':'>' , 'LP':'(' , 'RP':')' , 'C':','}

                    if escape.startswith("u"):
                        digits = escape[1:]

                        for i in digits:
                            if i not in string.hexdigits:
                                raise UnableToLegacyDemangle(inpstr)    

                        c = int(digits,16)
                        disp += chr(c)

                        rest = after_escape
                        continue 
                    
                    else:
                        disp += unescaped[escape]
                        rest = after_escape
                        continue
                
                elif ("$" or ".") in rest:
                    dollar = rest.find("$")
                    dot = rest.find(".")

                    if dollar == -1:        
                        disp += rest[:dot]
                        rest = rest[dot:]
                        continue

                    if dot == -1:           
                        disp += rest[:dollar]
                        rest = rest[dollar:]
                        continue

                    if dollar < dot:
                        disp += rest[:dollar]
                        rest = rest[dollar:]
                    else:
                        disp += rest[:dot]
                        rest = rest[dot:]
                else:
                    break
            disp += rest    

        self.suffix = inn[1:]
        if self.suffix:
            if self.suffix.startswith(".") and self.is_symbol_like(self.suffix):
                disp += self.suffix

        return disp  
            
    def is_symbol_like(self,suffix):
        for i in suffix:
            if i.isalnum() or self.is_ascii_punctuation(i):
                continue
            else:
                return False

        return True

    def is_ascii_punctuation(self,c):
        if c in string.punctuation:
            return True
        else:
            return False

    def is_rust_hash(self, s):
        if s.startswith("h"):
            for i in s[1:]:
                if i not in string.hexdigits:
                    return False
            return True
        else:
            return False 

    def sanity_check(self, inpstr : str):
        for i in inpstr:
            if(ord(i) & 0x80 != 0):
                raise UnableToLegacyDemangle(inpstr)

        self.elements = 0  
        c = 0
        while inpstr[c] != "E":
            len = 0
            if not inpstr[c].isdigit():
                raise UnableToLegacyDemangle(inpstr)

            while inpstr[c].isdigit():                
                len = len *10 + int(inpstr[c])
                c += 1
            
            c += len
            self.elements += 1

## rust_v0.py

class UnableTov0Demangle(Exception):
    def __init__(self, given_str, message="Not able to demangle the given string using v0Demangler"):
        self.message = message
        self.given_str = given_str
        super().__init__(self.message)
    
    def __str__(self):
        return f'[{self.given_str}] {self.message}'

class V0Demangler(object):

    def __init__(self):
        self.disp = ""
        self.suffix = ""

    def demangle(self, inpstr : str) -> str:
        
        self.inpstr = inpstr[inpstr.index("R") + 1:]
        self.sanity_check(self.inpstr)

        if ".llvm." in inpstr:
            l = self.inpstr.find(".llvm.")
            candidate = self.inpstr[l+6:]
            for i in candidate: 
                if i not in string.hexdigits + "@":
                    raise UnableTov0Demangle(inpstr) 
            self.inpstr = self.inpstr[:l]   

        self.parser = Parser(self.inpstr,0)
        self.parser.skip_path()
        if (len(self.parser.inn) > self.parser.next_val) and self.parser.inn[self.parser.next_val].isupper():
            self.parser.skip_path()

        parser = Parser(self.inpstr,0)
        printer = Printer(parser,self.disp,0)
        printer.print_path(True)

        if "." in self.inpstr:
            self.suffix = self.inpstr[self.inpstr.index("."):len(self.inpstr)]
        
        return printer.out + self.suffix

    def sanity_check(self, inpstr : str):
        if not inpstr[0].isupper():
            raise UnableTov0Demangle(inpstr)

        for i in inpstr:
            if(ord(i) & 0x80 != 0):
                raise UnableTov0Demangle(inpstr)
       

class Ident(object):
    def __init__(self,ascii,punycode):
        self.ascii = ascii
        self.punycode = punycode
        self.small_punycode_len = 128
        self.disp = ""

    def try_small_punycode_decode(self):
        global out 
        global out_len

        def f(inp):
            inp = "".join(inp)
            self.disp += inp 
            return "Ok"
            
        out = ['\0'] * self.small_punycode_len
        out_len = 0
        r = self.punycode_decode()

        if r == "Error":
            return
        else:
            return f(out[:out_len])

    def insert(self,i,c):
        global out 
        global out_len

        j = out_len
        out_len += 1

        while j > i:
            out[j] = out[j-1]
            j -= 1
        out[i] = c
        return

    def punycode_decode(self):
        count = 0
        punycode_bytes = self.punycode
        try:
            punycode_bytes[count]
        except Exception:
            return "Error"

        lent = 0
        for c in self.ascii:
            self.insert(lent,c) 
            lent += 1

        base = 36
        t_min = 1
        t_max = 26
        skew = 38
        damp = 700
        bias = 72
        i = 0
        n = 0x80
        while True:
            delta = 0
            w = 1
            k = 0
            while True:
                k += base
                t = min(max((k-bias),t_min),t_max)
                d = punycode_bytes[count] 
                count += 1
                if d in string.ascii_lowercase:
                    d = ord(d)-ord('a')
                elif d in string.digits:
                    d = 26+(ord(d)-ord('0'))
                else:
                    return "Error"

                delta= delta + (d * w)
                if d < t:
                    break
                w *= (base-t)
            
            lent += 1
            i += delta
            n += i//lent
            i %= lent
            
            try:
                c = chr(n)
            except Exception:
                return "Error"

            self.insert(i,c) 
            i += 1

            try:
                punycode_bytes[count]
            except Exception:
                return 
            
            delta = delta//damp
            damp = 2

            delta += delta//lent
            k = 0
            while delta > ((base - t_min) * t_max)//2:
                delta = delta//(base - t_min)
                k += base
            bias = k + ((base - t_min + 1) * delta) // (delta + skew)


    def display(self):
        if self.try_small_punycode_decode():
            return
        else:
            if self.punycode:
                self.disp += "punycode{"

                if self.ascii:
                    self.disp += self.ascii
                    self.disp += "-"
                self.disp += self.punycode
                self.disp += "}"
            else:
                self.disp += self.ascii

def basic_type(tag):
    tagval = {'b':'bool','c':'char','e':'str','u':'()','a':'i8','s':'i16','l':'i32','x':'i64','n':'i128','i':'isize','h':'u8','t':'u16','m':'u32','y':'u64','o':'u128','j':'usize','f':'f32','d':'f64','z':'!','p':'_','v':'...'}
    if tag in tagval.keys():
        return tagval[tag]
    else:
        return

class Parser(object):
    
    def __init__(self,inn,next_val):
        self.inn = inn
        self.next_val = next_val

    def peek(self):
        return self.inn[self.next_val]

    def eat(self, b : bytes):
        if self.peek() == b:
            self.next_val += 1
            return True
        else:
            return False

    def next_func(self):
        b = self.peek()
        self.next_val += 1
        return b 

    def hex_nibbles(self):
        start = self.next_val
        while True:
            n = self.next_func()
            if n.isdigit() or (n in "abcdef") :
                continue
            elif n == "_":
                break
            else:
                raise UnableTov0Demangle(self.inn)
        return self.inn[start:self.next_val-1]

    def digit_10(self):
        d = self.peek()
        if d.isdigit():
            d = int(d)
        else:
            return "Error"
        self.next_val += 1
        return d
    
    def digit_62(self):
        d = self.peek()
        if d.isdigit():
            d = int(d)
        elif d.islower():
            d = 10 + (ord(d) - ord("a"))
        elif d.isupper():
            d = 10 + 26 + (ord(d) - ord("A"))
        else:
            raise UnableTov0Demangle(self.inn)
        self.next_val += 1
        return d

    def integer_62(self):
        if self.eat('_'):
            return 0
        x = 0
        while not self.eat('_'):
            d = self.digit_62()
            x *= 62
            x += d
        return x+1
        
    def opt_integer_62(self,tag: str):
        if not self.eat(tag):
            return 0
        return self.integer_62() + 1 

    def disambiguator(self):
        return self.opt_integer_62('s')
        
    def namespace(self): 
        n = self.next_func()
        if n.isupper():
            return n 
        elif n.islower():
            return
        else:
            raise UnableTov0Demangle(self.inn)
        
    def backref(self):
        s_start = self.next_val - 1
        i = self.integer_62()
        if i >= s_start:
            raise UnableTov0Demangle(self.inn)

        return Parser(self.inn,i)
    
    def ident(self):
        is_punycode = self.eat('u')
        l = self.digit_10()
        if l != 0:
            while True:
                d = self.digit_10()
                if d == "Error":
                    break
                l *= 10
                l += d
      
        self.eat('_')

        start = self.next_val
        self.next_val += l
        if self.next_val > len(self.inn):
            raise UnableTov0Demangle(self.inn)
        
        ident = self.inn[start:self.next_val]
        if is_punycode:
            if '_' in ident:
                i = len(ident) - ident[::-1].index("_") - 1 
                idt = Ident(ident[:i],ident[i+1:])
            else:
                idt = Ident("",ident)

            if not idt.punycode:
                raise UnableTov0Demangle(self.inn)
            
            return idt

        else:
            idt = Ident(ident,"")
            return idt

    
    def skip_path(self):
        val = self.next_func()
        if val.startswith('C'):
            self.disambiguator()
            self.ident()
        elif val.startswith('N'):
            self.namespace()
            self.skip_path()
            self.disambiguator()
            self.ident()

        elif val.startswith('M'):
            self.disambiguator()
            self.skip_path()
            self.skip_type()

        elif val.startswith('X'):
            self.disambiguator()
            self.skip_path()
            self.skip_type()
            self.skip_path()

        elif val.startswith('Y'):
            self.skip_type()
            self.skip_path()

        elif val.startswith('I'):
            self.skip_path()
            while not self.eat('E'):
                self.skip_generic_arg()

        elif val.startswith('B'):
            self.backref()
        
        else:
            raise UnableTov0Demangle(self.inn) 

    def skip_generic_arg(self):
        if self.eat('L'):
            self.integer_62()
        elif self.eat('K'):
            self.skip_const()
        else:
            self.skip_type()
        

    def skip_type(self):
        n = self.next_func()
        tag = n
        if basic_type(tag): 
            pass
        elif n == 'R' or n == 'Q':
            if self.eat('L'):
                self.integer_62()
            else:
                self.skip_type()
        elif n == 'P' or n == 'O' or n == 'S':
            self.skip_type()
        elif n == 'A':
            self.skip_type()
            self.skip_const()
        elif n == 'T':
            while not self.eat('E'):
                self.skip_type()
        elif n == 'F':
            _binder = self.opt_integer_62('G')
            _is_unsafe = self.eat('U')
            if self.eat('K'):
                c_abi = self.eat('C')
                if not c_abi:
                    abi = self.ident()
                    if abi.ascii or (not abi.punycode):   
                        raise UnableTov0Demangle(self.inn)
            while not self.eat('E'):
                self.skip_type()
            self.skip_type()
        elif n == 'D':
            _binder = self.opt_integer_62('G')
            while not self.eat('E'):
                self.skip_path()
                while self.eat('p'):
                    self.ident()
                    self.skip_type()
            if not self.eat("L"):
                raise UnableTov0Demangle(self.inn)
            self.integer_62()
        elif n == 'B':
            self.backref()
        else:
            self.next_val -= 1
            self.skip_path()
    
    def skip_const(self):
        if self.eat('B'):
            self.backref()
            return 

        ty_tag = self.next_func()
        if ty_tag == 'p' :
            return 
        type1 = ['h','t','m','y','o','j','b','c']
        type2 = ['a','s','l','x','n','i']

        if ty_tag in type1: 
            pass
        elif ty_tag in type2:
            _ = self.eat('n')
        else:
            raise UnableTov0Demangle(self.inn)
        self.hex_nibbles()
        return 

class Printer(object):
    def __init__(self,parser,out,bound):
        self.parser = parser
        self.out = out
        self.bound_lifetime_depth = bound

    def parser_macro(self,method):
        p = self.parser_mut() 
        
        if "(" in method:
           arg = method.split("\'")[1]
           method = method.split("\'")[0][:-1] 
           try:
               return getattr(p,method)(*arg)
           except Exception:
               self.out += "?"

        try:
            return getattr(p,method)()
        except Exception:
            self.out += "?"

    def invalid(self):
        self.out += '?'
        print(self.out)
        raise UnableTov0Demangle("Error")

    def parser_mut(self):
        return self.parser

    def eat(self,b):
        par = self.parser_mut()
        if par.eat(b):
            return True
        else:
            return False
    
    def backref_printer(self):
        p = self.parser_mut()
        return Printer(p.backref(),self.out,self.bound_lifetime_depth)

    def print_lifetime_from_index(self,lt):
        self.out += "'"
        if lt == 0:
            self.out += "_" 
        depth = self.bound_lifetime_depth - lt
        if depth :
            if depth<26:
                c = ord("a") + depth
                self.out += str(c)     
            else:
                self.out += "_"
                self.out += str(depth)
        else:
            self.invalid()

    def in_binder(self,val):

        def f1():
            is_unsafe = self.eat('U')
            if self.eat('K'):
                if self.eat('C'):
                    abi = 'C'
                else:
                    ab = self.parser_macro("ident")
                    if not ab.ascii or ab.punycode:
                        self.invalid()
                    abi = ab.ascii
            else:
                abi = None
            
            if is_unsafe:
                self.out += "unsafe "
            
            if abi:
                self.out += 'extern \"'
                parts = abi.split('_')
                for part in parts:
                    self.out += part
                    self.out += '-'
                
                self.out += '\"'

            self.out += "fn("
            self.print_sep_list("print_type",", ") 
            self.out += ")"

            if self.eat('u'):
                pass
            else:
                self.out += " -> "
                self.print_type() 

            return ""

        def f2():
            self.print_sep_list("print_dyn_trait"," + ")
            return ""

        bound_lifetimes = self.parser_macro("opt_integer_62('G')")

        if bound_lifetimes > 0:
            self.out += 'for<'
            for i in range(bound_lifetimes):
                if i > 0:
                    self.out += ', '
                self.bound_lifetime_depth += 1
                self.print_lifetime_from_index(1)
            
            self.out += '> '
        
        if val == 1:
            r = f1()
        if val == 2:
            r = f2()
        self.bound_lifetime_depth -= bound_lifetimes

        return r

    def print_sep_list(self,f,sep):
        i = 0
        while not self.eat('E'):
            if i > 0:
                self.out += str(sep)
            getattr(self,f)() 
            i += 1
        return i

    def print_path(self,in_value):
        tag = self.parser_macro("next_func")
        if tag=="C":
            dis = self.parser_macro("disambiguator")
            name = self.parser_macro("ident")
            name.display()
            self.out += name.disp

        elif tag == 'N':
            ns = self.parser_macro("namespace")
            self.print_path(in_value)
            dis = self.parser_macro("disambiguator")
            name = self.parser_macro("ident")        
            if ns:
                self.out += "::{"
                if ns == "C":
                    self.out += "closure"
                elif ns == "S":
                    self.out += "shim"
                else:
                    self.out += ns
                if not name.ascii or (not name.punycode):
                    self.out += ":"
                    name.display()
                    self.out += name.disp

                self.out += "#"
                self.out += str(dis)
                self.out += "}"
            else:
                if name.ascii or name.punycode:
                    self.out += "::"
                    name.display()
                    self.out += name.disp

        elif tag == "M" or tag == "X" or tag == "Y":
            if tag!="Y":
                self.parser_macro("disambiguator")
                self.parser_macro("skip_path")
        
            self.out += "<"
            self.print_type()

            if tag != "M":
                self.out += " as "
                self.print_path(False)

            self.out += ">"

        elif tag == "I":
            self.print_path(in_value)
            if in_value:
                self.out += "::"

            self.out += "<"
            self.print_sep_list("print_generic_arg", ", ")
            self.out += ">"

        elif tag == "B":
            prin = self.backref_printer()
            prin.print_type()
            self.out = prin.out 
        
        else:
            self.invalid()

    def print_generic_arg(self):
        if self.eat('L'):
            lt = self.parser_macro("integer_62")
            self.print_lifetime_from_index(lt)
        elif self.eat('K'):
            self.print_const()
        else:
            self.print_type()

    def print_type(self):
        tag = self.parser_macro("next_func")
        if basic_type(tag):
            ty = basic_type(tag)
            self.out += ty
            return

        if tag == 'R' or tag == 'Q':
            self.out += '&'
            if self.eat('L'):
                lt = self.parser_macro("integer_62")
                if lt != 0:
                    self.print_lifetime_from_index(lt)
                    self.out += ' '
            
            if tag != 'R':
                self.out += "mut "

            self.print_type()
        
        elif tag == 'P' or tag == 'O':
            self.out += '*'
            if tag != 'P':
                self.out += "mut "
            else:
                self.out += "const "
            self.print_type()

        elif tag == 'A' or tag == 'S':
            self.out += '['
            self.print_type()

            if tag == 'A':
                self.out += '; '
                self.print_const()
            self.out += ']'
        
        elif tag == 'T':
            self.out += '('
            count = self.print_sep_list("print_type",", ")
            if count == 1:
                self.out += ","
            self.out += ")"

        elif tag == 'F':
            self.in_binder(1) 

        elif tag == 'D':
            self.out += "dyn "
            self.in_binder(2)
 
            if not self.eat('L'):
                self.invalid()
            
            lt = self.parser_macro("integer_62")
            if lt != 0:
                self.out += " + "
                self.print_lifetime_from_index(lt)
        
        elif tag == 'B':
            prin = self.backref_printer()
            prin.print_type()
            self.out = prin.out

        else:
            p = self.parser_mut()
            p.next_val -= 1
            self.print_path(False)


    def print_path_maybe_open_generics(self):
        if self.eat('B'):
            self.backref_printer().print_path_maybe_open_generics()

        elif self.eat('I'):
            self.print_path(False)
            self.out += "<"
            self.print_sep_list("print_generic_arg",", ")
            return True
        else:
            self.print_path(False)
            return False
    
    def print_dyn_trait(self):
        open = self.print_path_maybe_open_generics()

        while self.eat('p'):
            if not open:
                self.out += "<"
                open = True
            else:
                self.out += ", "
            
            name = self.parser_macro("ident")
            name.display()
            self.out += name.disp
            self.out += " = "
            self.print_type()

        if open:
            self.out += ">"

    def print_const(self):
        if self.eat('B'):
            return self.backref_printer().print_const()

        ty_tag = self.parser_macro("next_func")
        if ty_tag == 'p':
            self.out += "_"
            return 
        
        type1 = ['h','t','m','y','o','j']
        type2 = ['a','s','l','x','n','i']

        if ty_tag in type1:
            self.print_const_uint()
        elif ty_tag in type2:
            self.print_const_int()
        elif ty_tag == 'b':
            self.print_const_bool()
        elif ty_tag == 'c':
            self.print_const_char()
        else:
            self.invalid()

        return 

    def print_const_uint(self):
        hex_val = self.parser_macro("hex_nibbles")

        if len(hex_val) > 16:
            self.out += "0x"
            self.out += hex_val
            return

        self.out += str(int(hex_val,16))

    def print_const_int(self):
        if self.eat('n'):
            self.out += "-"
        self.print_const_uint()

    def print_const_bool(self):
        hex_val = self.parser_macro("hex_nibbles")

        if hex_val == '0':
            self.out += "false"
        elif hex_val == '1':
            self.out += "true"
        else:
            self.invalid()
        
    def print_const_char(self):
        hex_val = self.parser_macro("hex_nibbles")

        if len(hex_val) > 8:
            self.invalid()

        char_val = "0x"
        char_val += hex_val
        c = chr(int(char_val,16))
        self.out += repr(c)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
