// https://github.com/libyal/libexe/blob/4b74c91226e7d174bdff74315129bc17b956d564/documentation/Executable%20(EXE)%20file%20format.asciidoc#5-resource-section-data    opt_header.windows_fields.

// we use identifier names from the C headers for PE structures,
// which don't match the Rust style guide.
// example: `IMAGE_DOS_HEADER`
// don't show compiler warnings when encountering these names.
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};
use log::debug;

use crate::{aspace::AddressSpace, loader::pe::PE, RVA};

pub struct ResourceSectionData {
    buf: Vec<u8>,
}

impl ResourceSectionData {
    #[allow(clippy::unnecessary_wraps)]
    fn read_u16(&self, offset: usize) -> Result<u16> {
        // TODO: bounds check
        let buf = &self.buf[offset..offset + 2];
        Ok(LittleEndian::read_u16(buf))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn read_u32(&self, offset: usize) -> Result<u32> {
        // TODO: bounds check
        let buf = &self.buf[offset..offset + 4];
        Ok(LittleEndian::read_u32(buf))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn read_buf(&self, offset: usize, length: usize) -> Result<Vec<u8>> {
        // TODO: bounds check
        Ok(self.buf[offset..offset + length].to_vec())
    }

    pub fn root(&self) -> Result<ResourceNode> {
        ResourceNode::read(self, 0x0)
    }

    pub fn from_pe(pe: &PE) -> Result<Option<ResourceSectionData>> {
        let opt_header = match pe.optional_header {
            None => return Ok(None),
            Some(opt_header) => opt_header,
        };

        let rsrc_table = match opt_header.data_directories.get_resource_table() {
            None => return Ok(None),
            Some(rsrc_table) => rsrc_table,
        };

        debug!(
            "rsrc: table at {:#x}-{:#x}",
            pe.module.address_space.base_address + rsrc_table.virtual_address as RVA,
            pe.module.address_space.base_address + rsrc_table.virtual_address as RVA + rsrc_table.size as RVA
        );

        let buf = pe.module.address_space.read_bytes(
            // goblin calls this a "virtual address", but its actually an RVA.
            pe.module.address_space.base_address + rsrc_table.virtual_address as RVA,
            rsrc_table.size as usize,
        )?;

        Ok(Some(ResourceSectionData { buf }))
    }
}

struct ResourceNodeHeader {
    _flags:            u32,
    _timestamp:        u32,
    _major_version:    u16,
    _minor_version:    u16,
    named_entry_count: u16,
    id_entry_count:    u16,
}

impl ResourceNodeHeader {
    fn read(rsrc: &ResourceSectionData, offset: usize) -> Result<ResourceNodeHeader> {
        Ok(ResourceNodeHeader {
            _flags:            rsrc.read_u32(offset)?,
            _timestamp:        rsrc.read_u32(offset + 4)?,
            _major_version:    rsrc.read_u16(offset + 8)?,
            _minor_version:    rsrc.read_u16(offset + 10)?,
            named_entry_count: rsrc.read_u16(offset + 12)?,
            id_entry_count:    rsrc.read_u16(offset + 14)?,
        })
    }
}

#[derive(Clone)]
pub struct ResourceNodeEntry {
    id:     u32,
    offset: u32,
}

impl ResourceNodeEntry {
    fn read(rsrc: &ResourceSectionData, offset: usize) -> Result<ResourceNodeEntry> {
        Ok(ResourceNodeEntry {
            id:     rsrc.read_u32(offset)?,
            offset: rsrc.read_u32(offset + 4)?,
        })
    }

    fn has_name(&self) -> bool {
        self.id & 0x8000_0000 > 0
    }

    fn is_branch_node(&self) -> bool {
        self.offset & 0x8000_0000 > 0
    }

    pub fn id(&self, rsrc: &ResourceSectionData) -> Result<NodeIdentifier> {
        let offset = self.id & 0x7FFF_FFFF;
        if self.has_name() {
            Ok(NodeIdentifier::Name(
                ResourceNodeName::read(rsrc, offset as usize)?.name()?,
            ))
        } else {
            Ok(NodeIdentifier::ID(offset))
        }
    }

    pub fn child(&self, rsrc: &ResourceSectionData) -> Result<NodeChild> {
        let offset = (self.offset & 0x7FFF_FFFF) as usize;
        if self.is_branch_node() {
            Ok(NodeChild::Node(ResourceNode::read(rsrc, offset)?))
        } else {
            Ok(NodeChild::Data(ResourceDataDescriptor::read(rsrc, offset)?))
        }
    }
}

pub struct ResourceNode {
    _header:       ResourceNodeHeader,
    named_entries: Vec<ResourceNodeEntry>,
    id_entries:    Vec<ResourceNodeEntry>,
}

impl ResourceNode {
    fn read(rsrc: &ResourceSectionData, offset: usize) -> Result<ResourceNode> {
        let header = ResourceNodeHeader::read(rsrc, offset)?;
        let mut named_entries = vec![];
        let mut id_entries = vec![];

        let mut offset = offset + 16;
        for _ in 0..header.named_entry_count {
            named_entries.push(ResourceNodeEntry::read(rsrc, offset)?);
            offset += 8;
        }
        for _ in 0..header.id_entry_count {
            id_entries.push(ResourceNodeEntry::read(rsrc, offset)?);
            offset += 8;
        }

        Ok(ResourceNode {
            _header: header,
            named_entries,
            id_entries,
        })
    }

    pub fn get_child_by_name(&self, rsrc: &ResourceSectionData, name: &str) -> Result<Option<NodeChild>> {
        for child in self.named_entries.iter() {
            match child.id(rsrc)? {
                NodeIdentifier::ID(_) => continue,
                NodeIdentifier::Name(child_name) => {
                    if child_name == name {
                        return Ok(Some(child.child(rsrc)?));
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn get_child_by_id(&self, rsrc: &ResourceSectionData, id: u32) -> Result<Option<NodeChild>> {
        for child in self.id_entries.iter() {
            match child.id(rsrc)? {
                NodeIdentifier::Name(_) => continue,
                NodeIdentifier::ID(i) => {
                    if i == id {
                        return Ok(Some(child.child(rsrc)?));
                    }
                }
            }
        }
        Ok(None)
    }

    // TODO: might want to make this an iterator, one day.
    pub fn children(&self, rsrc: &ResourceSectionData) -> Result<Vec<(ResourceNodeEntry, NodeChild)>> {
        let mut ret = vec![];

        for entry in self.named_entries.iter().cloned() {
            let child = entry.child(rsrc)?;
            ret.push((entry, child));
        }

        for entry in self.id_entries.iter().cloned() {
            let child = entry.child(rsrc)?;
            ret.push((entry, child));
        }

        Ok(ret)
    }
}

#[derive(Debug)]
pub enum ResourceDataType {
    RT_CURSOR       = 1,
    RT_BITMAP       = 2,
    RT_ICON         = 3,
    RT_MENU         = 4,
    RT_DIALOG       = 5,
    RT_STRING       = 6,
    RT_FONTDIR      = 7,
    RT_FONT         = 8,
    RT_ACCELERATOR  = 9,
    RT_RCDATA       = 10,
    RT_MESSAGETABLE = 11,
    RT_GROUP_CURSOR = 12,
    RT_GROUP_ICON   = 14,
    RT_VERSION      = 16,
    RT_DLGINCLUDE   = 17,
    RT_PLUGPLAY     = 19,
    RT_VXD          = 20,
    RT_ANICURSOR    = 21,
    RT_ANIICON      = 22,
    RT_HTML         = 23,
    RT_MANIFEST     = 24,
}

impl ResourceDataType {
    pub fn from_u32(v: u32) -> Option<ResourceDataType> {
        match v {
            1 => Some(ResourceDataType::RT_CURSOR),
            2 => Some(ResourceDataType::RT_BITMAP),
            3 => Some(ResourceDataType::RT_ICON),
            4 => Some(ResourceDataType::RT_MENU),
            5 => Some(ResourceDataType::RT_DIALOG),
            6 => Some(ResourceDataType::RT_STRING),
            7 => Some(ResourceDataType::RT_FONTDIR),
            8 => Some(ResourceDataType::RT_FONT),
            9 => Some(ResourceDataType::RT_ACCELERATOR),
            10 => Some(ResourceDataType::RT_RCDATA),
            11 => Some(ResourceDataType::RT_MESSAGETABLE),
            12 => Some(ResourceDataType::RT_GROUP_CURSOR),
            14 => Some(ResourceDataType::RT_GROUP_ICON),
            16 => Some(ResourceDataType::RT_VERSION),
            17 => Some(ResourceDataType::RT_DLGINCLUDE),
            19 => Some(ResourceDataType::RT_PLUGPLAY),
            20 => Some(ResourceDataType::RT_VXD),
            21 => Some(ResourceDataType::RT_ANICURSOR),
            22 => Some(ResourceDataType::RT_ANIICON),
            23 => Some(ResourceDataType::RT_HTML),
            24 => Some(ResourceDataType::RT_MANIFEST),
            _ => None,
        }
    }
}

pub enum NodeIdentifier {
    Name(String),
    ID(u32),
}

struct ResourceNodeName {
    character_buf: Vec<u8>,
}

impl ResourceNodeName {
    fn read(rsrc: &ResourceSectionData, offset: usize) -> Result<ResourceNodeName> {
        let character_count = rsrc.read_u16(offset)?;
        let character_buf = rsrc.read_buf(offset + 2, 2 * character_count as usize)?;
        Ok(ResourceNodeName { character_buf })
    }

    fn name(&self) -> Result<String> {
        let chars: Vec<u16> = self.character_buf.chunks_exact(2).map(LittleEndian::read_u16).collect();

        widestring::U16String::from_vec(chars).to_string().map_err(|e| e.into())
    }
}

pub struct ResourceDataDescriptor {
    pub rva:  u32,
    pub size: u32,
}

impl ResourceDataDescriptor {
    fn read(rsrc: &ResourceSectionData, offset: usize) -> Result<ResourceDataDescriptor> {
        Ok(ResourceDataDescriptor {
            rva:  rsrc.read_u32(offset)?,
            size: rsrc.read_u32(offset + 4)?,
        })
    }

    pub fn data(&self, pe: &PE) -> Result<Vec<u8>> {
        pe.module
            .address_space
            .relative
            .read_bytes(self.rva as RVA, self.size as usize)
    }
}

pub enum NodeChild {
    Node(ResourceNode),
    Data(ResourceDataDescriptor),
}
