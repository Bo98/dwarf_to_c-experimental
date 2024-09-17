# By Bo98

from elftools.common.utils import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.dwarf.datatype_cpp import DIE_name, parse_cpp_datatype
from pathlib import Path
import io, json, re, shutil, sys

offset_to_definitions = {}
processed_offsets = set()

def safe_get_attr(die, attr, default):
	return die.attributes[attr].value if attr in die.attributes else default

def get_relative_subname(full_die, relative_die):
	def get_die_namearr(die):
		namearr = []
		cur_die = die
		while cur_die.tag != "DW_TAG_compile_unit":
			if "DW_AT_specification" in cur_die.attributes:
				cur_die = cur_die.get_DIE_from_attribute("DW_AT_specification")
			if "DW_AT_name" in cur_die.attributes:
				namearr.append(DIE_name(cur_die))
			cur_die = cur_die.get_parent()
		namearr.reverse()
		return namearr

	die1_name = get_die_namearr(full_die)
	die2_name = get_die_namearr(relative_die)

	common = 0
	for i, part in enumerate(die1_name):
		if i >= len(die2_name) or part != die2_name[i]:
			common = i
			break

	return "::".join(die1_name[common:])

def describe_cpp_datatype(var_die):
	type_desc = parse_cpp_datatype(var_die)
	if type_desc.tag == "structure" and type_desc.name == "structure ":
		type_die = var_die.get_DIE_from_attribute("DW_AT_type")
		for _ in range(len(type_desc.modifiers)):
			type_die = type_die.get_DIE_from_attribute("DW_AT_type")
		if "DW_AT_specification" in type_die.attributes:
			type_desc.name = get_relative_subname(type_die.get_DIE_from_attribute("DW_AT_specification"), type_die.get_parent())
	return str(type_desc)


_RECURSE_FILENAMES_CACHE = {}
def recurse_filenames(definition):
	if definition.die_offset in _RECURSE_FILENAMES_CACHE:
		return _RECURSE_FILENAMES_CACHE[definition.die_offset]
	filenames = set()
	filenames.add(definition.file)
	for child in definition.children:
		filenames.update(recurse_filenames(child))
	_RECURSE_FILENAMES_CACHE[definition.die_offset] = filenames
	return filenames

_SUB_REGEXES = {}
with open("dwarf_to_c.json") as f:
	config_data = json.load(f)
	config_data[r"(\.\.\\)+"] = ""
	config_data["[<>]"] = "_"
	for key, value in config_data.items():
		_SUB_REGEXES[re.compile(key.replace("/", r"(/|\\)"), re.IGNORECASE)] = value

class Definition:
	def __init__(self, die):
		self.children = []
		self.toplevel = (die.tag == "DW_TAG_compile_unit" or die.get_parent().tag == "DW_TAG_compile_unit")
		self.die_offset = die.offset

		if "DW_AT_decl_file" in die.attributes:
			lineprogram = die.dwarfinfo.line_program_for_CU(die.cu)
			file_index = die.attributes["DW_AT_decl_file"].value

			dwarf5 = lineprogram.header.version >= 5
			if not dwarf5:
				file_index -= 1

			if file_index < 0:
				self.file = None
				self.line = None
			elif file_index >= len(lineprogram.header.file_entry):
				suffix = ""
				if "DW_AT_name" in die.attributes:
					suffix = f" for {DIE_name(die)}"
				print(f"Failed fo find file{suffix} at index: {file_index}")
				self.file = None
				self.line = None
			else:
				file_entry = lineprogram.header.file_entry[file_index - 1]
				dir_index = file_entry.dir_index if dwarf5 else file_entry.dir_index - 1
				if dir_index >= 0:
					directory = lineprogram.header.include_directory[dir_index]
				else:
					directory = b""
				self.file = str(Path(bytes2str(directory), bytes2str(file_entry.name)))
				for regex, substitute in _SUB_REGEXES.items():
					self.file = regex.sub(substitute, self.file)
				if ":" in self.file or self.file[0] == '\\' or self.file[0] == '/' or self.file[0] == ".":
					raise RuntimeError(f"Non-relative path detected: {self.file}")
				self.file = Path(self.file)

				self.line = safe_get_attr(die, "DW_AT_decl_line", None)
		else:
			self.file = None
			self.line = None

	def add_child(self, child):
		self.children.append(child)

	def to_source(self, file, filename, indent=""):
		if self.file:
			print(indent + f"// {self.file.name}{':' + str(self.line) if self.line else ''}", file=file)

class CompileUnitDefinition(Definition):
	def to_source(self, file, filename, indent=""):
		raise NotImplementedError

class TypedefDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		self.basetype = describe_cpp_datatype(die)
		self.name = DIE_name(die)
		self.accessibility = safe_get_attr(die, "DW_AT_accessibility", 0)

	def to_source(self, file, filename, indent=""):
		if self.toplevel and self.file != filename:
			return
		super().to_source(file, filename, indent)
		print(indent + f"typedef {self.basetype} {self.name};", file=file)
		print(file=file)

class UsingDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		self.name = get_relative_subname(die.get_DIE_from_attribute("DW_AT_import"), die.get_parent())
		self.accessibility = safe_get_attr(die, "DW_AT_accessibility", 0)

	def to_source(self, file, filename, indent=""):
		if self.toplevel and self.file != filename:
			return
		super().to_source(file, filename, indent)
		print(indent + f"using {self.name};", file=file)
		print(file=file)

class UsingNamespaceDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		import_die = die.get_DIE_from_attribute("DW_AT_import")
		if "DW_AT_name" in import_die.attributes:
			self.name = get_relative_subname(import_die, die.get_parent())
		else:
			self.name = None

	def to_source(self, file, filename, indent=""):
		if self.toplevel and self.file != filename:
			return
		super().to_source(file, filename, indent)
		if self.name:
			print(indent + f"using namespace {self.name};", file=file)
		else:
			print(indent + "/* using namespace {self.name}; */", file=file)
		print(file=file)

class NamespaceDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		if "DW_AT_name" in die.attributes:
			self.name = DIE_name(die)
		else:
			self.name = None

	def to_source(self, file, filename, indent=""):
		if self.toplevel and self.file != filename and (filename is None or filename not in recurse_filenames(self)):
			return
		super().to_source(file, filename, indent)
		print(indent + f"namespace {(self.name + ' ') if self.name else ''}{'{'}", file=file)
		for child in self.children:
			child_filenames = recurse_filenames(child)
			if (child_filenames == {None} and self.file == filename) or (filename is not None and (child.file == filename or filename in child_filenames)):
				child.to_source(file, filename, indent + "\t")
		print(indent + "}", file=file)
		print(file=file)

class StructureDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		if "DW_AT_specification" in die.attributes:
			self.name = get_relative_subname(die.get_DIE_from_attribute("DW_AT_specification"), die.get_parent())
		elif "DW_AT_name" in die.attributes:
			self.name = DIE_name(die)
		else:
			self.name = None
		self.inherits = []
		self.declaration = safe_get_attr(die, "DW_AT_declaration", False)
		self.accessibility = safe_get_attr(die, "DW_AT_accessibility", 0)
		self.member = False
		if "DW_AT_type" in die.attributes:
			raise RuntimeError("!!!")

	def add_inherit(self, die):
		inherit = ""
		if "DW_AT_accessibility" in die.attributes:
			accessibility = die.attributes["DW_AT_accessibility"].value
			match accessibility:
				case 1:
					inherit = "public "
				case 2:
					inherit = "protected "
				case 3:
					inherit = "private "
				case _:
					raise RuntimeError(f"Unexpected accessibility {accessibility}")
		inherit += describe_cpp_datatype(die)
		self.inherits.append(inherit)

	def to_source(self, file, filename, indent=""):
		if self.toplevel and self.file != filename:
			return
		super().to_source(file, filename, indent)
		if self.declaration and not self.children:
			print(indent + f"struct {self.name if self.name else ''}{(' : ' + ', '.join(self.inherits)) if self.inherits else ''};", file=file)
		else:
			if self.declaration:
				print(indent + "// Declaration", file=file)
			print(indent + f"struct {(self.name + ' ') if self.name else ''}{(': ' + ', '.join(self.inherits) + ' ') if self.inherits else ''}{'{'}", file=file)
			accessibility = -1
			for child in self.children:
				if (isinstance(child, UnionDefinition) or isinstance(child, StructureDefinition)) and child.member:
					continue
				if child.accessibility != accessibility:
					match child.accessibility:
						case 1:
							print(indent + "public:", file=file)
						case 2:
							print(indent + "protected:", file=file)
						case 3:
							print(indent + "private:", file=file)
						case _:
							if accessibility != -1:
								print(indent + "\t// Unknown accessibility", file=file)
							#raise RuntimeError(f"Unexpected accessibility {child.accessibility}")
							pass
					if child.accessibility != 0:
						accessibility = child.accessibility
				child.to_source(file, filename, indent + "\t")
			print(indent + "}", file=file)
		print(file=file)

class FormalParameterDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)

		if safe_get_attr(die, "DW_AT_artificial", False):
			self.type = None
			return

		if die.tag == "DW_TAG_unspecified_parameters":
			self.type = "..."
			self.name = None
			self.value = None
		else:
			if "DW_AT_abstract_origin" in die.attributes:
				original_die = die.get_DIE_from_attribute("DW_AT_abstract_origin")
				self.name = get_relative_subname(original_die, die.get_parent())
				self.type = None
			else:
				type_die = die.get_DIE_from_attribute("DW_AT_type")
				if type_die.tag == "DW_TAG_ptr_to_member_type":
					containing_type_die = type_die.get_DIE_from_attribute("DW_AT_containing_type")
					if containing_type_die.tag == "DW_TAG_structure_type" and "DW_AT_specification" in containing_type_die.attributes:
						ptr_prefix = get_relative_subname(containing_type_die.get_DIE_from_attribute("DW_AT_specification"), containing_type_die.get_parent())
					else:
						ptr_prefix = DIE_name(containing_type_die)
					# TODO: do this properly					
					self.type = f"/* ptr to member of {ptr_prefix} */ &" + describe_cpp_datatype(type_die)
				else:
					self.type = describe_cpp_datatype(die)

				if "DW_AT_name" in die.attributes:
					self.name = f" {DIE_name(die)}"
				else:
					self.name = None

			self.value = safe_get_attr(die, "DW_AT_const_value", None)
			if isinstance(self.value, bytes):
				self.value = f'"{bytes2str(self.value)}"'
			if "DW_AT_default_value" in die.attributes:
				if self.value:
					raise RuntimeError("Unexpected default value.")
				default_val_die = die.get_DIE_from_attribute("DW_AT_default_value")
				if default_val_die.tag != "DW_TAG_variable":
					print(die)
					print(default_val_die)
					raise RuntimeError("Unsupported default value.")
				self.value = DIE_name(default_val_die)

	def to_source(self, file, filename, indent=""):
		if self.type:
			super().to_source(file, filename, indent)
			print(indent + f"({self.type}){self.name if self.name else 'unknown_arg'}{(' = ' + str(self.value)) if self.value else ''}", file=file)

class SubprogramDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		if "DW_AT_specification" in die.attributes:
			self.name = get_relative_subname(die.get_DIE_from_attribute("DW_AT_specification"), die.get_parent())
		elif "DW_AT_abstract_origin" in die.attributes:
			self.name = get_relative_subname(die.get_DIE_from_attribute("DW_AT_abstract_origin"), die.get_parent())
		else:
			self.name = DIE_name(die)
		self.declaration = safe_get_attr(die, "DW_AT_declaration", False)
		self.external = safe_get_attr(die, "DW_AT_external", False)
		self.accessibility = safe_get_attr(die, "DW_AT_accessibility", 1)
		self.virtuality = safe_get_attr(die, "DW_AT_virtuality", 0)

		self.const = bytes2str(safe_get_attr(die, "DW_AT_MIPS_linkage_name", b"")).startswith("_ZNK")

		if self.virtuality == 2 and not self.declaration:
			raise RuntimeError("!!!")

		self.return_type = "void"
		if "DW_AT_type" in die.attributes:
			self.return_type = describe_cpp_datatype(die)
		else:
			parent = die.get_parent()
			if parent.tag == "DW_TAG_structure_type":
				if "DW_AT_specification" in parent.attributes:
					parent_name = get_relative_subname(parent.get_DIE_from_attribute("DW_AT_specification"), parent.get_parent())
				elif "DW_AT_name" in parent.attributes:
					parent_name = DIE_name(parent)
				if self.name == parent_name or self.name == f"~{parent_name}":
					self.return_type = None

		if die.get_parent().tag == "DW_TAG_structure_type":
			self.external = False

		self.parameters = []

	def add_parameter(self, definition):
		if not definition.type:
			return

		parameter_source = definition.type.strip()
		if definition.name:
			parameter_source += f" {definition.name}"
		if definition.value:
			parameter_source += f" = {definition.value}"

		self.parameters.append(parameter_source)

	def to_source(self, file, filename, indent=""):
		if self.toplevel and self.file != filename:
			return
		super().to_source(file, filename, indent)
		signature = f"{'extern ' if self.external else ''}{'virtual ' if self.virtuality > 0 else ''}{self.return_type + ' ' if self.return_type else ''}{self.name}({', '.join(self.parameters)}){' const' if self.const else ''}"
		if self.declaration and not self.children:
			print(indent + signature + f"{' = 0' if self.virtuality == 2 else ''};", file=file)
		else:
			if self.declaration:
				print(indent + "// Declaration", file=file)
			print(indent + signature + " {", file=file)
			print(indent + "\t// This is not intended to be complete source code - just some variable hints. Consult a decompiler.", file=file)
			for child in self.children:
				child.to_source(file, filename, indent + "\t")
			print(indent + "}", file=file)
		print(file=file)

class EnumerationDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		if "DW_AT_name" in die.attributes:
			self.name = DIE_name(die)
		else:
			self.name = None
		if "DW_AT_type" in die.attributes:
			self.type = describe_cpp_datatype(die)
		else:
			self.type = None
		self.accessibility = safe_get_attr(die, "DW_AT_accessibility", 0)

	def to_source(self, file, filename, indent=""):
		if self.toplevel and self.file != filename:
			return
		super().to_source(file, filename, indent)
		print(indent + f"enum {(self.name + ' ') if self.name else ''}{(': ' + self.type + ' ') if self.type else ''}{'{'}", file=file)
		for child in self.children:
			child.to_source(file, filename, indent + "\t")
		print(indent + "}", file=file)
		print(file=file)

class EnumeratorDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		self.name = DIE_name(die)
		self.value = die.attributes["DW_AT_const_value"].value

	def to_source(self, file, filename, indent=""):
		super().to_source(file, filename, indent)
		print(indent + f"{self.name} = {self.value},", file=file)

class UnionDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		if "DW_AT_specification" in die.attributes:
			self.name = get_relative_subname(die.get_DIE_from_attribute("DW_AT_specification"), die.get_parent())
		elif "DW_AT_name" in die.attributes:
			self.name = DIE_name(die)
		else:
			self.name = None
		self.accessibility = safe_get_attr(die, "DW_AT_accessibility", 0)
		self.member = False
		if "DW_AT_type" in die.attributes:
			raise RuntimeError("!!!")

	def to_source(self, file, filename, indent=""):
		if self.toplevel and self.file != filename:
			return
		super().to_source(file, filename, indent)
		print(indent + f"union {(self.name + ' ') if self.name else ''}{'{'}", file=file)
		for child in self.children:
			child.to_source(file, filename, indent + "\t")
		print(indent + "}", file=file)

class MemberDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		if "DW_AT_name" in die.attributes:
			self.name = DIE_name(die)
		else:
			self.name = None

		type_die = die.get_DIE_from_attribute("DW_AT_type")
		if (type_die.tag == "DW_TAG_union_type" or type_die.tag == "DW_TAG_structure_type") and ("DW_AT_name" not in type_die.attributes and "DW_AT_specification" not in type_die.attributes):
			# if type_die.get_parent().tag == "DW_TAG_member":
			# 	raise RuntimeError("Unsupported reused anonymous union.")

			if type_die.offset in processed_offsets:
				self.definition = offset_to_definitions[type_die.offset]
			else:
				if type_die.tag == "DW_TAG_structure_type":
					self.definition = StructureDefinition(type_die)
				else:
					self.definition = UnionDefinition(type_die)
				offset_to_definitions[type_die.offset] = self.definition
				processed_offsets.add(type_die.offset)
			self.definition.member = True
			self.type = None
		else:
			self.type = describe_cpp_datatype(die)
			self.definition = None

		#if self.type and not self.name:
		#	raise RuntimeError("!!!")

		self.accessibility = safe_get_attr(die, "DW_AT_accessibility", 0)
		self.last_member = ("DW_AT_sibling" not in die.attributes)

	def to_source(self, file, filename, indent=""):
		if self.toplevel and self.file != filename:
			return
		super().to_source(file, filename, indent)
		if self.definition:
			with io.StringIO() as sio:
				self.definition.to_source(sio, filename, indent)
				definition_source = sio.getvalue()
				if self.name:
					definition_source = definition_source.rstrip("; ") + f" {self.name};\n"
				file.write(definition_source)
		else:
			print(indent + f"{self.type} {self.name};", file=file)
		if self.last_member:
			print(file=file)

class VariableDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		if "DW_AT_specification" in die.attributes:
			self.original_die = die.get_DIE_from_attribute("DW_AT_specification")
			self.name = get_relative_subname(self.original_die, die.get_parent())
			self.type = None
		elif "DW_AT_abstract_origin" in die.attributes:
			self.original_die = die.get_DIE_from_attribute("DW_AT_abstract_origin")
			self.name = get_relative_subname(self.original_die, die.get_parent())
			self.type = None
		else:
			self.original_die = None
			if "DW_AT_name" in die.attributes:
				self.name = DIE_name(die)
			else:
				self.name = None # why?
			self.type = describe_cpp_datatype(die)
		self.external = safe_get_attr(die, "DW_AT_external", False)
		self.accessibility = safe_get_attr(die, "DW_AT_accessibility", 0)
		self.declaration = safe_get_attr(die, "DW_AT_declaration", False) # TODO?
		self.value = safe_get_attr(die, "DW_AT_const_value", None)
		if isinstance(self.value, bytes):
			self.value = f'"{bytes2str(self.value)}"'
		if not self.declaration and self.original_die:
			self.omit = (self.value == safe_get_attr(self.original_die, "DW_AT_const_value", None))
		else:
			self.omit = False

	def to_source(self, file, filename, indent=""):
		if self.toplevel and self.file != filename:
			return
		super().to_source(file, filename, indent)
		if not self.omit:
			print(indent + f"{'extern ' if self.external else ''}{(self.type + ' ') if self.type else ''}{self.name or ''}{(' = ' + str(self.value) if self.value else '')};", file=file)
			print(file=file)

class LexicalBlockDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)

	def to_source(self, file, filename, indent=""):
		super().to_source(file, filename, indent)
		print(indent + "{", file=file)
		for child in self.children:
			child.to_source(file, filename, indent + "\t")
		print(indent + "}", file=file)

class InlinedSubroutineDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		self.name = get_relative_subname(die.get_DIE_from_attribute("DW_AT_abstract_origin"), die.get_parent())

	def to_source(self, file, filename, indent=""):
		super().to_source(file, filename, indent)
		print(indent + f"{self.name}(/* parameters */);", file=file)

class LabelDefinition(Definition):
	def __init__(self, die):
		super().__init__(die)
		self.name = DIE_name(die)

	def to_source(self, file, filename, indent=""):
		super().to_source(file, filename, indent)
		print(indent[:-1] + f"{self.name}:", file=file)

def assert_children_tags(die, tags):
	if die.has_children and not tags:
		raise RuntimeError("Expected no children but got some.")
	elif not die.has_children and tags:
		raise RuntimeError("Expected children but got none.")
	for child in die.iter_children():
		if die.tag not in tags:
			raise RuntimeError(f"Unsupported tag {tag} in {die.tag}.")

def process_die(die, parent=None):
	if die.offset in processed_offsets:
		return
	processed_offsets.add(die.offset)
	definition = None
	match die.tag:
		case "DW_TAG_typedef":
			definition = TypedefDefinition(die)
			assert_children_tags(die, [])
		case "DW_TAG_base_type" | "DW_TAG_pointer_type" | "DW_TAG_reference_type" | "DW_TAG_const_type" | "DW_TAG_array_type" | "DW_TAG_volatile_type" | "DW_TAG_subroutine_type" | "DW_TAG_ptr_to_member_type":
			if die.get_parent().tag != "DW_TAG_compile_unit":
				raise RuntimeError(f"Unexpected {die.tag}.")
		case "DW_TAG_imported_declaration":
			definition = UsingDefinition(die)
			assert_children_tags(die, [])
		case "DW_TAG_imported_module":
			definition = UsingNamespaceDefinition(die)
			assert_children_tags(die, [])
		case "DW_TAG_namespace":
			definition = NamespaceDefinition(die)
			for child in die.iter_children():
				process_die(child, definition)
		case "DW_TAG_structure_type":
			definition = StructureDefinition(die)
			for child in die.iter_children():
				process_die(child, definition)
		case "DW_TAG_subprogram":
			definition = SubprogramDefinition(die)
			for child in die.iter_children():
				process_die(child, definition)
		case "DW_TAG_formal_parameter" | "DW_TAG_unspecified_parameters":
			definition = FormalParameterDefinition(die)
			if isinstance(parent, SubprogramDefinition):
				parent.add_parameter(definition)
				definition = None
			assert_children_tags(die, [])
		case "DW_TAG_enumeration_type":
			definition = EnumerationDefinition(die)
			for child in die.iter_children():
				process_die(child, definition)
		case "DW_TAG_enumerator":
			definition = EnumeratorDefinition(die)
			assert_children_tags(die, [])
		case "DW_TAG_union_type":
			definition = UnionDefinition(die)
			for child in die.iter_children():
				process_die(child, definition)
		case "DW_TAG_member":
			definition = MemberDefinition(die)
			assert_children_tags(die, [])
		case "DW_TAG_variable":
			definition = VariableDefinition(die)
			assert_children_tags(die, [])
		case "DW_TAG_inheritance":
			parent.add_inherit(die)
			assert_children_tags(die, [])
		case "DW_TAG_lexical_block":
			if die.get_parent().tag != "DW_TAG_subprogram" and die.get_parent().tag != "DW_TAG_lexical_block":
				raise RuntimeError(f"Unexpected {die.tag}.")
			definition = LexicalBlockDefinition(die)
			for child in die.iter_children():
				process_die(child, definition)
		case "DW_TAG_inlined_subroutine":
			definition = InlinedSubroutineDefinition(die)
			# Ignore children
		case "DW_TAG_label":
			definition = LabelDefinition(die)
			assert_children_tags(die, [])
		case _:
			print(die)
			print(describe_cpp_datatype(die))
			print(parent)
			raise NotImplementedError(f"Unimplemented tag {die.tag}.")
	if definition:
		offset_to_definitions[die.offset] = definition
		parent.add_child(definition)

def main(filename, outdir):
	with open(filename, "rb") as f:
		elffile = ELFFile(f)

		if not elffile.has_dwarf_info():
			sys.exit("File has no DWARF data.")

		dwarfinfo = elffile.get_dwarf_info()
		definitions = []
		dbswork_regex = re.compile(r"^(C:\\WINDOWS\\TEMP|S:\\_SYS_T~2)\\DBSWORK\\a\\")
		for cu in dwarfinfo.iter_CUs():
			top_die = cu.get_top_DIE()
			definition = CompileUnitDefinition(top_die)

			path_leaf = dbswork_regex.sub("", str(top_die.get_full_path()))
			for regex, substitute in _SUB_REGEXES.items():
				path_leaf = regex.sub(substitute, path_leaf)
			print(f"Processing compile unit: {path_leaf}")
			if Path(path_leaf).is_absolute() or ":" in path_leaf or path_leaf[0] == ".":
				raise RuntimeError(f"Non-relative path detected: {path_leaf}")
			definition.file = Path("_compile") / Path(path_leaf)

			for child in top_die.iter_children():
				process_die(child, definition)
			definitions.append(definition)

		print()
		_RECURSE_FILENAMES_CACHE = {}
		outdir = Path(outdir)
		for definition in definitions:
			print(f"Writing data for compile unit: {definition.file.name}")
			for child in definition.children:
				filenames = recurse_filenames(child)
				for filename in filenames:
					file = filename
					if not file:
						file = definition.file
					if file.is_absolute():
						print(child)
						print(child.file)
						raise RuntimeError("Found child with an absolute file!")
					file = (outdir / file).resolve()
					file.parent.mkdir(parents=True, exist_ok=True)
					with file.open("a+") as f:
						f.seek(0)
						with io.StringIO() as sio:
							child.to_source(sio, filename)
							string = sio.getvalue()
							if string not in f.read():
								f.write(string)
		print("Done")

if __name__ == '__main__':
	if len(sys.argv) != 3:
		sys.exit("Invalid arguments.")
	main(sys.argv[1], sys.argv[2])
