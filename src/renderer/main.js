FolderSelectScreen.init();
ScanProgressScreen.init();
ResultsScreen.init();
SettingsScreen.init();

IpcClient.getSettings().then((settings) => {
  if (!settings.setupComplete) SettingsScreen.showOnboarding();
});
