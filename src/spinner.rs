use spinners::Spinner;
use termimad::{crossterm, MadSkin};

pub async fn spinner<'a, T, F, R, TFut, FAfter, TAfter>(text: T, func: F, after: FAfter) -> TAfter
where
    T: AsRef<str>,
    F: Fn() -> TFut + 'a,
    TFut: Future<Output = R> + 'a,
    FAfter: FnOnce(Spinner, R) -> TAfter + 'a,
{
    let mut skin = MadSkin::default();
    skin.bold.set_fg(crossterm::style::Color::Magenta);
    let loader = Spinner::new(
        spinners::Spinners::Dots,
        skin.inline(text.as_ref()).to_string(),
    );
    let result = func().await;
    after(loader, result)
}
