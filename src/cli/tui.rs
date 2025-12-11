use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;

use crossterm::{event, execute, terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}};
use ratatui::{backend::CrosstermBackend, Terminal};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::style::{Style, Color, Modifier};

use crate::cli::types::Connection;

pub async fn run_tui(state: Arc<RwLock<HashMap<String, Vec<Connection>>>>, kube_mode: bool, did_fetch_once: Arc<AtomicBool>) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let refresh_interval = Duration::from_millis(1000);
    let mut last_refresh = tokio::time::Instant::now();

    enum Focus { Nodes, Shared, Connections }
    enum SortMode { None, ByState }
    enum FilterMode { None, Established, TimeWait }
    enum InputMode { Normal, Searching }

    let mut selected = 0usize;
    let mut show_details = false;
    let mut focus = Focus::Nodes;
    let mut conn_selected = 0usize;
    let mut sort_mode = SortMode::None;
    let mut shared_selected = 0usize;
    let mut pair_filter: Option<(String, String)> = None;
    let mut filter_mode = FilterMode::None;
    let mut input_mode = InputMode::Normal;
    let mut search_buffer = String::new();
    let mut search_ip: Option<String> = None;

    let mut modal_dismissed = false;
    loop {
        let map = state.read().await.clone();
        let mut nodes: Vec<_> = map.keys().cloned().collect();
        nodes.sort();

        let mut ip_sets: HashMap<String, HashSet<String>> = HashMap::new();
        for (node, conns) in &map {
            let mut s = HashSet::new();
            for c in conns {
                s.insert(c.src_ip.clone());
                s.insert(c.dst_ip.clone());
            }
            ip_sets.insert(node.clone(), s);
        }

        let mut ip_to_nodes: HashMap<String, Vec<String>> = HashMap::new();
        for (node, ips) in &ip_sets {
            for ip in ips {
                ip_to_nodes.entry(ip.clone()).or_default().push(node.clone());
            }
        }

        let mut edges: HashMap<(String, String), (usize, String)> = HashMap::new();
        for (node, conns) in &map {
            for c in conns {
                for (other_node, other_ips) in &ip_sets {
                    if other_node == node { continue; }
                    if other_ips.contains(&c.src_ip) || other_ips.contains(&c.dst_ip) {
                        let a = node;
                        let b = other_node;
                        let key = if a <= b { (a.clone(), b.clone()) } else { (b.clone(), a.clone()) };
                        let sample_ip = if other_ips.contains(&c.src_ip) { c.src_ip.clone() } else { c.dst_ip.clone() };
                        let entry = edges.entry(key).or_insert((0usize, sample_ip));
                        entry.0 += 1;
                    }
                }
            }
        }

        let mut edge_list: Vec<((String, String), (usize, String))> = edges.into_iter().collect();
        edge_list.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));

        terminal.draw(|f| {
            let size = f.area();
            let outer = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)].as_ref())
                .split(size);
            let top = outer[0];
            let status_area = outer[1];

            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(25), Constraint::Percentage(75)].as_ref())
                .split(top);

            let right_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
                .split(chunks[1]);

            let items: Vec<ListItem> = nodes.iter().map(|n| {
                let c = map.get(n).map(|v| v.len()).unwrap_or(0);
                ListItem::new(format!("{} ({})", n, c))
            }).collect();
            let mut stateful = ratatui::widgets::ListState::default();
            if !nodes.is_empty() {
                stateful.select(Some(selected.min(nodes.len()-1)));
            }
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Nodes"))
                .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .highlight_symbol("» ");
            f.render_stateful_widget(list, chunks[0], &mut stateful);

            let shared_items: Vec<ListItem> = edge_list.iter().map(|((a,b),(count,ip))| {
                ListItem::new(format!("{} <-> {} ({}) [{}]", a, b, count, ip))
            }).collect();
            let mut shared_state = ratatui::widgets::ListState::default();
            if !shared_items.is_empty() {
                shared_state.select(Some(shared_selected.min(shared_items.len()-1)));
            }
            let shared_list = List::new(shared_items)
                .block(Block::default().borders(Borders::ALL).title("Shared"))
                .highlight_style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))
                .highlight_symbol("» ");
            f.render_stateful_widget(shared_list, right_chunks[0], &mut shared_state);

            let selected_node = nodes.get(selected).cloned();
            if show_details {
                let mut conns: Vec<Connection> = Vec::new();
                if let Some((ref a, ref b)) = pair_filter {
                    if let Some(list_a) = map.get(a) {
                        if let Some(other_ips) = ip_sets.get(b) {
                            for c in list_a.iter() {
                                if other_ips.contains(&c.src_ip) || other_ips.contains(&c.dst_ip) {
                                    conns.push(c.clone());
                                }
                            }
                        }
                    }
                    if let Some(list_b) = map.get(b) {
                        if let Some(other_ips) = ip_sets.get(a) {
                            for c in list_b.iter() {
                                if other_ips.contains(&c.src_ip) || other_ips.contains(&c.dst_ip) {
                                    conns.push(c.clone());
                                }
                            }
                        }
                    }
                } else if let Some(node) = selected_node {
                    conns = map.get(&node).cloned().unwrap_or_default();
                }

                if let Some(ref ip) = search_ip {
                    conns.retain(|c| c.src_ip.contains(ip) || c.dst_ip.contains(ip));
                }

                match filter_mode {
                    FilterMode::Established => {
                        conns.retain(|c| c.state.eq_ignore_ascii_case("ESTABLISHED"));
                    }
                    FilterMode::TimeWait => {
                        conns.retain(|c| c.state.eq_ignore_ascii_case("TIME_WAIT") || c.state.eq_ignore_ascii_case("TIME-WAIT"));
                    }
                    FilterMode::None => {}
                }

                if let SortMode::ByState = sort_mode {
                    conns.sort_by(|a, b| a.state.cmp(&b.state));
                }

                let items: Vec<ListItem> = conns.iter().map(|c| {
                    let line = format!("{:<6} {:<22} {:<22} {:<12}", c.proto, format!("{}:{}", c.src_ip, c.src_port), format!("{}:{}", c.dst_ip, c.dst_port), c.state);
                    ListItem::new(line)
                }).collect();

                if !items.is_empty() {
                    let mut list_state = ratatui::widgets::ListState::default();
                    if conn_selected >= items.len() { conn_selected = items.len() - 1; }
                    list_state.select(Some(conn_selected));

                    let title = match sort_mode {
                        SortMode::None => "Connections",
                        SortMode::ByState => "Connections (sorted by state)",
                    };
                    let list = List::new(items)
                        .block(Block::default().borders(Borders::ALL).title(title))
                        .highlight_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                        .highlight_symbol("» ");
                    f.render_stateful_widget(list, right_chunks[1], &mut list_state);
                } else {
                    let paragraph = Paragraph::new("(no node selected)")
                        .block(Block::default().borders(Borders::ALL).title("Connections"));
                    f.render_widget(paragraph, right_chunks[1]);
                }
            } else {
                let paragraph = Paragraph::new("Press Right or Enter to view connections for the selected node. Use Up/Down to choose a node. Press 't' to toggle sort by state. Press 'f' to cycle state filter. Press 'p' to search by IP. Press 'q' to quit.")
                    .block(Block::default().borders(Borders::ALL).title("Connections"));
                f.render_widget(paragraph, right_chunks[1]);
            }
            let focus_str = match focus { Focus::Nodes => "Nodes", Focus::Shared => "Shared", Focus::Connections => "Connections" };
            let focus_color = match focus { Focus::Nodes => Color::Cyan, Focus::Shared => Color::Magenta, Focus::Connections => Color::Green };
            let status = format!("Focus: {} | Filter: {} | Search: {}{}",
                focus_str,
                match filter_mode { FilterMode::None => "none".to_string(), FilterMode::Established => "ESTABLISHED".to_string(), FilterMode::TimeWait => "TIME_WAIT".to_string(), },
                search_ip.as_deref().unwrap_or("<none>"),
                match input_mode {
                    InputMode::Searching => format!(" | typing: {}", search_buffer),
                    _ => "".to_string(),
                }
            );
            let sb = Paragraph::new(status)
                .block(Block::default().borders(Borders::ALL).title("Status"))
                .style(Style::default().fg(focus_color));
            f.render_widget(sb, status_area);

            let modal_visible = kube_mode && nodes.is_empty() && did_fetch_once.load(Ordering::SeqCst) && !modal_dismissed;
            if modal_visible {
                let mw = (size.width.saturating_mul(60)) / 100;
                let mh = (size.height.saturating_mul(30)) / 100;
                let mx = size.x + (size.width.saturating_sub(mw)) / 2;
                let my = size.y + (size.height.saturating_sub(mh)) / 2;
                let area = ratatui::layout::Rect::new(mx, my, mw, mh);
                let text = "No kflow-daemon pods found. Run `kflow install -n <ns>` or apply the provided k8s/daemonset.yaml. Press Enter or Esc to dismiss.";
                let p = Paragraph::new(text)
                    .block(Block::default().borders(Borders::ALL).title("No Daemon Pods"))
                    .style(Style::default().fg(Color::Red));
                f.render_widget(p, area);
            }
        })?;

        let conn_count = if let Some(node) = state.read().await.keys().cloned().collect::<Vec<_>>().get(selected) {
            let mut c = state.read().await.get(node).cloned().unwrap_or_default();
            if let Some(ref ip) = search_ip { c.retain(|x| x.src_ip.contains(ip) || x.dst_ip.contains(ip)); }
            match filter_mode {
                FilterMode::Established => c.retain(|x| x.state.eq_ignore_ascii_case("ESTABLISHED")),
                FilterMode::TimeWait => c.retain(|x| x.state.eq_ignore_ascii_case("TIME_WAIT") || x.state.eq_ignore_ascii_case("TIME-WAIT")),
                FilterMode::None => {}
            }
            if let SortMode::ByState = sort_mode { c.sort_by(|a,b| a.state.cmp(&b.state)); }
            c.len()
        } else { 0 };

        let timeout = refresh_interval.checked_sub(last_refresh.elapsed()).unwrap_or_default();
        if event::poll(timeout)? {
            if let event::Event::Key(key) = event::read()? {
                let modal_visible = kube_mode && nodes.is_empty() && !modal_dismissed;
                if modal_visible {
                    match key.code {
                        event::KeyCode::Enter | event::KeyCode::Esc | event::KeyCode::Char('c') => {
                            modal_dismissed = true;
                        }
                        _ => {}
                    }
                    continue;
                }

                if let InputMode::Searching = input_mode {
                    match key.code {
                        event::KeyCode::Esc => {
                            input_mode = InputMode::Normal;
                            search_buffer.clear();
                        }
                        event::KeyCode::Enter => {
                            if !search_buffer.trim().is_empty() {
                                search_ip = Some(search_buffer.trim().to_string());
                            } else {
                                search_ip = None;
                            }
                            input_mode = InputMode::Normal;
                        }
                        event::KeyCode::Backspace => { search_buffer.pop(); }
                        event::KeyCode::Char(c) => { search_buffer.push(c); }
                        _ => {}
                    }
                } else {
                    match key.code {
                        event::KeyCode::Char('q') => break,
                        event::KeyCode::Down => {
                            if let Focus::Nodes = focus {
                                if !state.read().await.is_empty() {
                                    selected = selected.saturating_add(1).min(state.read().await.len().saturating_sub(1));
                                    show_details = false;
                                    conn_selected = 0;
                                }
                            } else if let Focus::Shared = focus {
                                if !edge_list.is_empty() {
                                    shared_selected = shared_selected.saturating_add(1).min(edge_list.len().saturating_sub(1));
                                }
                            } else {
                                if conn_count > 0 {
                                    conn_selected = conn_selected.saturating_add(1).min(conn_count.saturating_sub(1));
                                }
                            }
                        }
                        event::KeyCode::Up => {
                            if let Focus::Nodes = focus {
                                if selected > 0 { selected -= 1; }
                                show_details = false;
                                conn_selected = 0;
                            } else if let Focus::Shared = focus {
                                if shared_selected > 0 { shared_selected -= 1; }
                            } else {
                                if conn_selected > 0 { conn_selected -= 1; }
                            }
                        }
                        event::KeyCode::Enter => {
                            if let Focus::Shared = focus {
                                if !edge_list.is_empty() && shared_selected < edge_list.len() {
                                    let ((a,b), _) = &edge_list[shared_selected];
                                    pair_filter = Some((a.clone(), b.clone()));
                                    show_details = true;
                                    focus = Focus::Connections;
                                    conn_selected = 0;
                                }
                            } else if let Focus::Nodes = focus {
                                pair_filter = None;
                                show_details = true;
                                focus = Focus::Connections;
                                conn_selected = 0;
                            } else {
                                show_details = !show_details;
                                if show_details { focus = Focus::Connections; } else { focus = Focus::Nodes; }
                            }
                        }
                        event::KeyCode::Right | event::KeyCode::Tab => {
                            let prev = match focus { Focus::Nodes => Focus::Nodes, Focus::Shared => Focus::Shared, Focus::Connections => Focus::Connections };
                            focus = match focus {
                                Focus::Nodes => Focus::Shared,
                                Focus::Shared => Focus::Connections,
                                Focus::Connections => Focus::Nodes,
                            };
                            if let Focus::Connections = focus {
                                if !show_details { show_details = true; }
                                if let Focus::Nodes = prev { pair_filter = None; }
                            }
                        }
                        event::KeyCode::Left => {
                            let prev = match focus { Focus::Nodes => Focus::Nodes, Focus::Shared => Focus::Shared, Focus::Connections => Focus::Connections };
                            focus = match focus {
                                Focus::Nodes => Focus::Connections,
                                Focus::Shared => Focus::Nodes,
                                Focus::Connections => Focus::Shared,
                            };
                            if let Focus::Connections = focus { if let Focus::Nodes = prev { pair_filter = None; } }
                        }
                        event::KeyCode::Char('r') => {}
                        event::KeyCode::Char('t') => {
                            sort_mode = match sort_mode {
                                SortMode::None => SortMode::ByState,
                                SortMode::ByState => SortMode::None,
                            };
                            conn_selected = 0;
                        }
                        event::KeyCode::Char('f') => {
                            filter_mode = match filter_mode {
                                FilterMode::None => FilterMode::Established,
                                FilterMode::Established => FilterMode::TimeWait,
                                FilterMode::TimeWait => FilterMode::None,
                            };
                            conn_selected = 0;
                        }
                        event::KeyCode::Char('p') => {
                            input_mode = InputMode::Searching;
                            search_buffer.clear();
                        }
                        event::KeyCode::Char('c') => {
                            pair_filter = None;
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_refresh.elapsed() >= refresh_interval {
            last_refresh = tokio::time::Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
