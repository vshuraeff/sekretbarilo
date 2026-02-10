// rule definitions and loading

/// a detection rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub regex_pattern: String,
    pub secret_group: usize,
    pub keywords: Vec<String>,
    pub entropy_threshold: Option<f64>,
}
