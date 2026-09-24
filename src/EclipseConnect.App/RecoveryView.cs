using System.IO;
using System.Windows;
using System.Windows.Controls;
using EclipseConnect.Core;

namespace EclipseConnect.App;

public partial class MainWindow
{
    private void ShowRecovery()
    {
        Header("Восстановление", "Вернуть выбор файла или профиля. Работающие подключения не переключаются.");
        PageContent.Children.Add(Text("Telegram", 18, true));
        PageContent.Children.Add(Muted("Выбран для следующего запуска: " + (installed.GetValueOrDefault("telegram")?.Version ?? "ещё не проверен")));
        var previous = settings.PreviousTelegramPath;
        PageContent.Children.Add(Muted(string.IsNullOrWhiteSpace(previous) ? "Предыдущий файл не выбран." : "Предыдущий файл: " + Path.GetFileName(previous)));
        var restore = Action("Вернуть предыдущий Telegram", () => RestoreTelegramChoice(), true);
        restore.IsEnabled = !qa && (!string.IsNullOrWhiteSpace(previous) || File.Exists(storage.Resolve("settings-before-update.json")));
        RowActions(restore);
        PageContent.Children.Add(Muted("Версия файла будет проверена перед выбором. Прокси, который работает сейчас, останется запущенным."));
        Rule();
        PageContent.Children.Add(Text("Профиль FIX", 18, true));
        try
        {
            var state = new FixChoiceStore(storage).Read();
            PageContent.Children.Add(Muted("Выбран: " + FixChoiceStore.Describe(state.Selected)));
            PageContent.Children.Add(Muted("Предыдущий: " + FixChoiceStore.Describe(state.Previous)));
        }
        catch (Exception e) when (e is IOException or InvalidDataException or System.Text.Json.JsonException)
        { PageContent.Children.Add(Muted("Сохранённый выбор недоступен. Файл не изменён. " + Redactor.Sanitize(e.Message))); }
        RowActions(Action("Открыть восстановление FIX", () => { Navigate("fix"); return Task.CompletedTask; }));
        PageContent.Children.Add(Muted("Выбор FIX восстанавливается в его управляющем окне. Чтобы остановить работающий FIX, используйте окно, из которого его запускали."));
        Rule();
        PageContent.Children.Add(Text("Если нужно отключить компонент", 18, true));
        RowActions(Action("Открыть компоненты", () => { Navigate("components"); return Task.CompletedTask; }));
        PageContent.Children.Add(Muted("Connect останавливает только собственные запуски. Чужие процессы, DNS и сетевые адаптеры эта страница не меняет."));
    }
    private async Task RestoreTelegramChoice()
    {
        if (qa || work != null) return;
        if (MessageBox.Show(this, "Вернуть предыдущий файл для следующего запуска? Работающий Telegram-прокси не будет остановлен.", "Восстановить выбор?", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await Run("Восстановление выбора Telegram", async ct =>
        {
            // Validate and hash the prospective restore without committing settings first.
            var candidate = new VersionSelection(storage, _ => { }).Restore(settings);
            var inspected = await Inventory.Inspect(Catalog.Telegram, candidate.TelegramPath, ct);
            var trusted = Catalog.KnownVersion(Catalog.Telegram, inspected.Hash) != "Не подтверждена";
            var prepared = updates.ReadPrepared(Catalog.Telegram);
            trusted |= prepared != null && string.Equals(prepared.Path, inspected.Path, StringComparison.OrdinalIgnoreCase) && prepared.Sha256 == inspected.Hash;
            if (!trusted) throw new InvalidDataException("Предыдущий файл не подтверждён. Настройки сохранены без изменений.");
            ct.ThrowIfCancellationRequested();
            storage.SaveSettings(candidate); settings = candidate;
            installed[Catalog.Telegram.Id] = inspected;
        });
    }
}
