pub fn main() {
    prost_build::Config::new()
        .btree_map(["."])
        //.message_attribute(".", "#[derive(Hash, Eq, Ord, PartialOrd)]")
        //.enum_attribute("event_type", "#[derive(Hash, Eq, Ord, PartialOrd)]")
        .out_dir("src/proto")
        .compile_protos(&["event.proto", "denm.proto"], &["schema"])
        .expect("Could not compile protobuf types in event.proto");
}
