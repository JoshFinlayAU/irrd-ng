//! `RPSLObject.generate_template()` (`irrd/rpsl/parser.py`), the body of
//! v4's `-t` whois response.

use crate::classes::ClassDef;
use crate::messages;

pub(crate) fn generate(class: &ClassDef) -> String {
    let max_name_width = class
        .fields
        .iter()
        .map(|f| f.name.chars().count())
        .max()
        .unwrap_or(0);
    let mut template = String::new();
    for field in class.fields {
        let mandatory = if field.optional {
            "[optional] "
        } else {
            "[mandatory]"
        };
        let single = if field.multiple {
            "[multiple]"
        } else {
            "[single]  "
        };
        let mut metadata: Vec<String> = Vec::new();
        if field.primary_key && field.lookup_key {
            metadata.push(messages::TEMPLATE_PRIMARY_LOOKUP_KEY.to_owned());
        } else if field.primary_key {
            metadata.push(messages::TEMPLATE_PRIMARY_KEY.to_owned());
        } else if field.lookup_key {
            metadata.push(messages::TEMPLATE_LOOKUP_KEY.to_owned());
        }
        let referring = field.kind.referring();
        if !referring.is_empty() {
            let reference_type = if field.kind.strong() { "strong" } else { "weak" };
            metadata.push(format!(
                "{reference_type} references {}",
                referring.join("/")
            ));
        }
        let padding = " ".repeat(max_name_width - field.name.chars().count());
        template.push_str(&format!(
            "{}: {padding}  {mandatory}  {single}  [{}]\n",
            field.name,
            metadata.join(", ")
        ));
    }
    template
}
