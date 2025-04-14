from mcp.server.fastmcp import FastMCP
import pymem
import ctypes
from pymem.ressources.structure import MEMORY_BASIC_INFORMATION
import struct

# Create an MCP server instance
mcp = FastMCP("MemMCP")

# Global state to store process handle, addresses, and last scanned data type
state = {
    "pm": None,
    "process_name": None,
    "addresses": [],
    "data_type": None  # Track the data type used in the last scan
}

def get_value_bytes(value, data_type):
    """Convert a value to bytes based on the specified data type."""
    if data_type == "int":
        return int(value).to_bytes(4, byteorder='little', signed=True)
    elif data_type == "float":
        return struct.pack('<f', float(value))  # Little-endian float
    elif data_type == "double":
        return struct.pack('<d', float(value))  # Little-endian double
    elif data_type == "bytes":
        try:
            # Expect value as a hex string (e.g., "DEADBEEF") or comma-separated bytes (e.g., "222,173,190,239")
            if isinstance(value, str) and ',' in value:
                byte_list = [int(b.strip()) & 0xFF for b in value.split(',')]
                return bytes(byte_list)
            return bytes.fromhex(value.replace(' ', ''))  # Convert hex string to bytes
        except:
            raise ValueError("Invalid bytes format. Use hex string (e.g., 'DEADBEEF') or comma-separated bytes (e.g., '222,173,190,239').")
    else:
        raise ValueError("Unsupported data type. Use 'int', 'float', 'double', or 'bytes'.")

def read_value(pm, address, data_type):
    """Read a value from memory based on the specified data type."""
    if data_type == "int":
        return pm.read_int(address)
    elif data_type == "float":
        return pm.read_float(address)
    elif data_type == "double":
        return pm.read_double(address)
    elif data_type == "bytes":
        byte_length = len(state["last_value_bytes"])  # Use length from initial scan
        return pm.read_bytes(address, byte_length)
    else:
        raise ValueError("Unsupported data type.")

def write_value(pm, address, value, data_type):
    """Write a value to memory based on the specified data type."""
    if data_type == "int":
        pm.write_int(address, int(value))
    elif data_type == "float":
        pm.write_float(address, float(value))
    elif data_type == "double":
        pm.write_double(address, float(value))
    elif data_type == "bytes":
        if isinstance(value, str):
            if ',' in value:
                byte_list = [int(b.strip()) & 0xFF for b in value.split(',')]
                pm.write_bytes(address, bytes(byte_list))
            else:
                pm.write_bytes(address, bytes.fromhex(value.replace(' ', '')))
        else:
            raise ValueError("Value for bytes must be a hex string or comma-separated bytes.")
    else:
        raise ValueError("Unsupported data type.")

@mcp.tool(
    name="scan",
    description="Scans the process memory for a specified value of a given data type."
)
def scan(process_name: str, value: str, data_type: str = "int") -> str:
    """
    Scans the process memory for a value of the specified data type.
    Args:
        process_name: Name of the process (e.g., "popcapgame1.exe")
        value: Value to search for (e.g., "25" for int, "3.14" for float, "DEADBEEF" for bytes)
        data_type: Type of value ("int", "float", "double", "bytes") [default: "int"]
    Returns:
        A string with the number of found addresses and instructions.
    """
    global state
    
    if state["pm"] and state["process_name"] != process_name:
        state["pm"].close_process()
        state["pm"] = None
    
    if not state["pm"]:
        try:
            state["pm"] = pymem.Pymem(process_name)
            state["process_name"] = process_name
            state["addresses"] = []
            result = f"Successfully attached to {process_name}."
        except pymem.exception.ProcessNotFound:
            return f"Process {process_name} not found. Ensure it’s running."
        except Exception as e:
            return f"Error attaching to {process_name}: {str(e)}"
    else:
        result = f"Using existing attachment to {process_name}."

    try:
        value_bytes = get_value_bytes(value, data_type)
        state["data_type"] = data_type
        state["last_value_bytes"] = value_bytes  # Store for bytes length reference
    except ValueError as e:
        return f"{result}\nError: {str(e)}"

    matches = []
    process_handle = state["pm"].process_handle
    address = 0x00000000
    max_address = 0x7FFFFFFF
    
    mbi = MEMORY_BASIC_INFORMATION()
    while address < max_address:
        try:
            ctypes.windll.kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address),
                                                  ctypes.byref(mbi), ctypes.sizeof(mbi))
            if mbi.State == 0x1000 and mbi.Protect in (0x04, 0x02, 0x20, 0x40):
                try:
                    region = state["pm"].read_bytes(address, mbi.RegionSize)
                    byte_length = len(value_bytes)
                    for i in range(len(region) - byte_length + 1):
                        if region[i:i+byte_length] == value_bytes:
                            matches.append(address + i)
                except:
                    pass
            address += mbi.RegionSize
        except:
            address += 0x1000
    
    state["addresses"] = matches
    count = len(matches)
    if count == 0:
        return f"{result}\nNo addresses found with {data_type} value {value}."
    return f"{result}\nFound {count} matching addresses with {data_type} value {value}. Call filter() with the new value after changing it in-game."

@mcp.tool(
    name="filter",
    description="Filters previously found addresses based on a new value of the same data type."
)
def filter(new_value: str) -> str:
    """
    Filters previously found addresses based on a new value of the same data type.
    Args:
        new_value: New value to filter by (e.g., "125" for int, "6.28" for float, "CAFEBABE" for bytes)
    Returns:
        A string with the number of remaining addresses and their details.
    """
    global state
    
    if not state["pm"]:
        return "No process attached. Run scan() first with a process name and initial value."
    if not state["addresses"]:
        return "No addresses to filter. Run scan() first with an initial value."
    if not state["data_type"]:
        return "No data type set. Run scan() first to specify a data type."
    
    try:
        value_bytes = get_value_bytes(new_value, state["data_type"])
    except ValueError as e:
        return f"Error: {str(e)}"
    
    filtered = []
    for addr in state["addresses"]:
        try:
            current_value = read_value(state["pm"], addr, state["data_type"])
            expected_value = struct.unpack('<f', value_bytes)[0] if state["data_type"] == "float" else \
                            struct.unpack('<d', value_bytes)[0] if state["data_type"] == "double" else \
                            value_bytes if state["data_type"] == "bytes" else int(new_value)
            if current_value == expected_value:
                filtered.append(addr)
        except:
            continue
    
    state["addresses"] = filtered
    count = len(filtered)
    
    if count == 0:
        return f"No addresses match the new {state['data_type']} value {new_value}. Try scanning again with scan()."
    elif count <= 5:
        details = "\nFinal candidates:\n" + "\n".join(
            [f"  0x{addr:X} -> {read_value(state['pm'], addr, state['data_type'])}"
             if read_value(state['pm'], addr, state['data_type']) is not None else f"  0x{addr:X} -> <unreadable>"
             for addr in filtered]
        )
        return f"Filtered to {count} addresses with {state['data_type']} value {new_value}.{details}\nCall edit() to modify these values or filter() again."
    else:
        return f"Filtered to {count} addresses with {state['data_type']} value {new_value}. Change the value in-game and call filter() again."

@mcp.tool(
    name="edit",
    description="Edits the values at the current list of addresses with the specified data type."
)
def edit(new_value: str) -> str:
    """
    Edits the values at the current list of addresses with the specified data type.
    Args:
        new_value: New value to write (e.g., "999" for int, "9.99" for float, "DEADBEEF" for bytes)
    Returns:
        A string with the results of the edit operation.
    """
    global state
    
    if not state["pm"]:
        return "No process attached. Run scan() first."
    if not state["addresses"]:
        return "No addresses to edit. Run scan() and filter() first."
    if not state["data_type"]:
        return "No data type set. Run scan() first to specify a data type."
    
    results = []
    for addr in state["addresses"]:
        try:
            write_value(state["pm"], addr, new_value, state["data_type"])
            results.append(f"  [✔] 0x{addr:X} updated to {new_value}")
        except Exception as e:
            results.append(f"  [✘] Failed to write to 0x{addr:X}: {str(e)}")
    
    return f"Edit results:\n" + "\n".join(results)

@mcp.tool(
    name="reset",
    description="Resets the state and closes the process handle."
)
def reset() -> str:
    """
    Resets the state and closes the process handle.
    """
    global state
    if state["pm"]:
        state["pm"].close_process()
    state = {"pm": None, "process_name": None, "addresses": [], "data_type": None}
    return "State reset and process handle closed."

@mcp.tool(
    name="get_addresses",
    description="Returns a specified number of addresses from the current list."
)
def get_addresses(count: int) -> str:
    """
    Returns a specified number of addresses from the current list.
    Args:
        count: Number of addresses to return (e.g., 5)
    Returns:
        A string with the requested number of addresses in hex format.
    """
    global state
    
    if not state["addresses"]:
        return "No addresses available. Run scan() and filter() first."
    
    available_count = len(state["addresses"])
    if count <= 0:
        return "Count must be greater than 0."
    
    return_count = min(count, available_count)
    addresses = state["addresses"][:return_count]
    formatted_addresses = [f"0x{addr:X}" for addr in addresses]
    return f"Returning {return_count} of {available_count} addresses:\n" + "\n".join(formatted_addresses)

# Run the server
if __name__ == "__main__":
    mcp.run()
    # for sse (endpoint: http://127.0.0.1:8000/sse)
    # mcp.run(transport="sse") 
