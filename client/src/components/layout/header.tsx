interface HeaderProps {
  title: string;
  description?: string;
}

export function Header({ title, description }: HeaderProps) {
  return (
    <header className="bg-card border-b border-border px-6 py-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-foreground">{title}</h2>
          {description && (
            <p className="text-muted-foreground">{description}</p>
          )}
        </div>
        <div className="flex items-center space-x-4">
          <button 
            className="relative p-2 text-muted-foreground hover:text-foreground transition-colors"
            data-testid="notifications-button"
          >
            <i className="fas fa-bell text-lg"></i>
            <span className="absolute -top-1 -right-1 w-5 h-5 bg-destructive text-destructive-foreground text-xs rounded-full flex items-center justify-center">
              3
            </span>
          </button>
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center">
              <span className="text-primary-foreground text-sm font-medium">AD</span>
            </div>
            <div className="text-sm">
              <div className="font-medium">Admin User</div>
              <div className="text-muted-foreground">System Administrator</div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
