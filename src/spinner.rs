use spinners::Spinner;
use termimad::{crossterm, MadSkin};

pub async fn spinner<'a, T, R, TFut, FAfter, TAfter>(text: T, fut: TFut, after: FAfter) -> TAfter
where
    T: AsRef<str>,
    TFut: Future<Output = R> + 'a,
    FAfter: FnOnce(Spinner, R) -> TAfter + 'a,
{
    let mut skin = MadSkin::default();
    skin.bold.set_fg(crossterm::style::Color::Magenta);
    let loader = Spinner::new(
        spinners::Spinners::Dots,
        skin.inline(text.as_ref()).to_string(),
    );
    let result = fut.await;
    after(loader, result)
}
