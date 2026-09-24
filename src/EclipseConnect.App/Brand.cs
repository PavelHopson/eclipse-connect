using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace EclipseConnect.App;

internal static class Brand
{
    public static BitmapImage Icon => new(new Uri("pack://application:,,,/Assets/Connect.ico"));
    public static void Apply(Window window, bool dark)
    {
        var colors = dark ? new[] { "#171B21", "#11151B", "#333E4D", "#B3BECD", "#94BCF6", "#22344D", "#F0F4FA", "#222A35" }
            : new[] { "#F8FAFD", "#EEF2F8", "#CCD5E2", "#52627A", "#255DA1", "#E3ECF9", "#17263C", "#FFFFFF" };
        var keys = new[] { "PageBrush", "SideBrush", "LineBrush", "MutedBrush", "AccentBrush", "SoftBrush", "TextBrush", "ControlBrush" };
        for (var i = 0; i < keys.Length; i++) window.Resources[keys[i]] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(colors[i]));
        window.Resources["PrimaryTextBrush"] = dark ? Brushes.Black : Brushes.White;
        window.Resources["SuccessBrush"] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(dark ? "#91D7B0" : "#23643F"));
        window.Resources["WarningBrush"] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(dark ? "#F0CD8B" : "#845014"));
        window.Resources["ErrorBrush"] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(dark ? "#F3A5AB" : "#A12336"));
        window.SetResourceReference(Window.BackgroundProperty, "PageBrush"); window.SetResourceReference(Window.ForegroundProperty, "TextBrush");
        window.Icon = Icon;
    }
}
