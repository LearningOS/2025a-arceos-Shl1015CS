use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use axfs_vfs::{VfsDirEntry, VfsError, VfsNodeAttr, VfsNodeOps, VfsNodeRef, VfsNodeType, VfsResult};
use axsync::Mutex;

use crate::file::FileNode;

/// A directory node in the RAM filesystem.
pub struct DirNode {
    parent: Mutex<Option<Weak<dyn VfsNodeOps>>>,
    children: Mutex<BTreeMap<String, VfsNodeRef>>,
}

impl DirNode {
    /// Create a new directory node.
    pub fn new(parent: Option<&VfsNodeRef>) -> Arc<Self> {
        let parent_weak = parent.map(Arc::downgrade);
        Arc::new(Self {
            parent: Mutex::new(parent_weak),
            children: Mutex::new(BTreeMap::new()),
        })
    }

    /// Set the parent directory.
    pub fn set_parent(&self, parent: Option<&VfsNodeRef>) {
        *self.parent.lock() = parent.map(Arc::downgrade);
    }

    fn create_node(&self, name: &str, ty: VfsNodeType) -> VfsResult {
        if name.is_empty() {
            return Err(VfsError::InvalidInput);
        }
        let mut children = self.children.lock();
        if children.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }

        let node: VfsNodeRef = match ty {
            VfsNodeType::File => Arc::new(FileNode::new()),
            VfsNodeType::Dir => Self::new(Some(&(self as &dyn VfsNodeOps).into())),
            _ => return Err(VfsError::Unsupported),
        };
        children.insert(name.into(), node);
        Ok(())
    }

    fn remove_node(&self, name: &str) -> VfsResult {
        let mut children = self.children.lock();
        if !children.contains_key(name) {
            return Err(VfsError::NotFound);
        }
        children.remove(name);
        Ok(())
    }
    pub fn do_rename(&self, src: &str, dst: &str) -> VfsResult {
        log::debug!("rename at ramfs: {} -> {}", src, dst);
        let (src_name, src_rest) = split_path(src);
        let (dst_name, dst_rest) = split_path(dst);

        if let Some(src_rest) = src_rest {
            match src_name {
                "" | "." => return self.do_rename(src_rest, dst),
                ".." => return self.parent().ok_or(VfsError::NotFound)?.rename(src_rest, dst),
                _ => {
                    let subdir = self
                        .children
                        .lock()
                        .get(src_name)
                        .ok_or(VfsError::NotFound)?
                        .clone();
                    return subdir.rename(src_rest, dst);
                }
            }
        }

        if let Some(dst_rest) = dst_rest {
            match dst_name {
                "" | "." => return self.do_rename(src, dst_rest),
                ".." => return self.parent().ok_or(VfsError::NotFound)?.rename(src, dst_rest),
                _ => {
                    let subdir = self
                        .children
                        .lock()
                        .get(dst_name)
                        .ok_or(VfsError::NotFound)?
                        .clone();
                    return subdir.rename(src, dst_rest);
                }
            }
        }

        if src_name.is_empty() || src_name == "." || src_name == ".." {
            return Err(VfsError::InvalidInput);
        }

        if dst_name.is_empty() || dst_name == "." || dst_name == ".." {
            return Err(VfsError::InvalidInput);
        }

        let mut children = self.children.lock();
        let node = children.get(src_name).ok_or(VfsError::NotFound)?.clone();

        if children.contains_key(dst_name) {
            children.remove(dst_name);
        }

        children.remove(src_name);
        children.insert(dst_name.to_string(), node);
        
        Ok(())
    }
}

impl VfsNodeOps for DirNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_dir(4096, 0))
    }

    fn parent(&self) -> Option<VfsNodeRef> {
        self.parent.lock().as_ref().and_then(|w| w.upgrade())
    }

    fn lookup(self: Arc<Self>, path: &str) -> VfsResult<VfsNodeRef> {
        log::debug!("lookup at ramfs: {}", path);
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            match name {
                "" | "." => self.lookup(rest),
                ".." => self
                    .parent()
                    .ok_or(VfsError::NotFound)?
                    .lookup(rest),
                _ => {
                    let subdir = self
                        .children
                        .lock()
                        .get(name)
                        .ok_or(VfsError::NotFound)?
                        .clone();
                    subdir.lookup(rest)
                }
            }
        } else {
            match name {
                "" | "." => Ok(self),
                ".." => Ok(self.parent().ok_or(VfsError::NotFound)?),
                _ => Ok(self
                    .children
                    .lock()
                    .get(name)
                    .ok_or(VfsError::NotFound)?
                    .clone()),
            }
        }
    }

    fn read_dir(&self, start_idx: usize, dirents: &mut [VfsDirEntry]) -> VfsResult<usize> {
        let children = self.children.lock();
        let mut idx = 0;
        for (name, node) in children.iter().skip(start_idx) {
            if idx >= dirents.len() {
                break;
            }
            let attr = node.get_attr().unwrap_or(VfsNodeAttr::default());
            dirents[idx] = VfsDirEntry {
                name: name.clone(),
                inode: idx as u64,
                ty: attr.file_type(),
            };
            idx += 1;
        }
        Ok(idx)
    }

    fn create(&self, path: &str, ty: VfsNodeType) -> VfsResult {
        log::debug!("create at ramfs: {} {:?}", path, ty);
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            match name {
                "" | "." => self.create(rest, ty),
                ".." => self.parent().ok_or(VfsError::NotFound)?.create(rest, ty),
                _ => {
                    if !self.children.lock().contains_key(name) {
                        self.create_node(name, VfsNodeType::Dir)?;
                    }
                    let subdir = self.children.lock().get(name).unwrap().clone();
                    subdir.create(rest, ty)
                }
            }
        } else if name.is_empty() || name == "." || name == ".." {
            Ok(()) // already exists
        } else {
            self.create_node(name, ty)
        }
    }

    fn remove(&self, path: &str) -> VfsResult {
        log::debug!("remove at ramfs: {}", path);
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            match name {
                "" | "." => self.remove(rest),
                ".." => self.parent().ok_or(VfsError::NotFound)?.remove(rest),
                _ => {
                    let subdir = self
                        .children
                        .lock()
                        .get(name)
                        .ok_or(VfsError::NotFound)?
                        .clone();
                    subdir.remove(rest)
                }
            }
        } else if name.is_empty() || name == "." || name == ".." {
            Err(VfsError::InvalidInput) // remove '.' or '..
        } else {
            self.remove_node(name)
        }
    }

    fn rename(&self, src: &str, dst: &str) -> VfsResult {
        self.do_rename(src, dst)
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> VfsResult<usize> {
        Err(VfsError::IsADirectory)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> VfsResult<usize> {
        Err(VfsError::IsADirectory)
    }

    fn fsync(&self) -> VfsResult {
        Err(VfsError::IsADirectory)
    }

    fn truncate(&self, _size: u64) -> VfsResult {
        Err(VfsError::IsADirectory)
    }
}

fn split_path(path: &str) -> (&str, Option<&str>) {
    let trimmed_path = path.trim_start_matches('/');
    trimmed_path.find('/').map_or((trimmed_path, None), |n| {
        (&trimmed_path[..n], Some(&trimmed_path[n + 1..]))
    })
}
