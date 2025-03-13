use std::path::Path;


pub(crate) trait PathLike {
    /// Retrieve the actual path that the object represents.
    ///
    /// That should be the entity that was opened.
    fn actual_path(&self) -> &Path;

    /// Retrieve the path that is being represented by this object.
    ///
    /// This is what the user thinks of as being used. E.g., consider
    /// the case of process symbolization and us working with
    /// `/proc/<xxx>/map_files/<file>` entries. The user doesn't think
    /// in terms of these paths, but is interested in whatever is being
    /// represented.
    fn represented_path(&self) -> &Path;
}

impl PathLike for Path {
    fn actual_path(&self) -> &Path {
        self
    }

    fn represented_path(&self) -> &Path {
        self
    }
}
