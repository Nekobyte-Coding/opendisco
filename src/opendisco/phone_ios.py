"""The iOS side of OpenDisco's phone screens (phone.py): UIKit through rubicon-objc.

Toga's iOS backend lays out the content but has no navigation, title-bar buttons, button styles,
share sheet or clipboard; these give phone.py those, under the names phone.py's docstring lists.

On an iPad at a regular width (full screen in either orientation, the larger side of Split View,
a wide Stage Manager window) the device list stays in a column at the left and the pages open
beside it, in a split view (_Split). At a compact width the iPad app is the iPhone's: pages are
pushed over the list. Changing between the two moves the open pages across.
"""
import math
from pathlib import Path

import toga
from toga.style import Pack

from opendisco import i18n
from opendisco.i18n import _, tr

# SF Symbols for the device page's tabs, in place of Toga's star on every one (by their English titles)
TAB_SYMBOLS = {"Details": "info.circle", "Packets": "doc.text.magnifyingglass", "Tools": "wrench.and.screwdriver",
               "Notes": "text.bubble", "Log": "list.bullet.rectangle"}
# and for Export's reports (phone.export_choices)
EXPORT_SYMBOLS = {"scan": "doc.richtext", "data": "tablecells", "security": "exclamationmark.shield",
                  "backups": "archivebox", "notes": "note.text", "log": "list.bullet.rectangle"}


def _objc(name):
    from rubicon.objc import ObjCClass
    return ObjCClass(name)


def _class_value(cls, name):
    """A class property (UIColor.systemRedColor...), however rubicon hands it over."""
    from rubicon.objc import ObjCInstance
    value = getattr(cls, name)
    return value if isinstance(value, ObjCInstance) else value()


class BarItem:
    """A title-bar button that app.py enables and disables like a Toga one (Export). One that
    opens a menu stays enabled: the menu's items say what there is to choose."""

    def __init__(self, native):
        self.native, self.menu = native, False

    @property
    def enabled(self) -> bool:
        return bool(self.native.isEnabled())

    @enabled.setter
    def enabled(self, value):
        self.native.enabled = bool(value) or self.menu


_NAV_WATCHER = None
_open_pages = []  # Pages pushed and not closed yet, to tell when Back took one off
_moving = False  # pages moving between the iPhone layout and the split view: not Back


def _nav_watcher():
    """The navigation controllers' delegate: after Back (the button or the swipe) a page that was
    on a stack is on none without its close() having run, and its on_back runs. (A page whose
    push waits for another page's closing animation isn't on the stack yet: not Back.)"""
    global _NAV_WATCHER
    if _NAV_WATCHER is None:
        from rubicon.objc import NSObject, objc_method

        class OpenDiscoNavigationWatcher(NSObject):
            @objc_method
            def navigationController_didShowViewController_animated_(self, nav, shown, animated: bool) -> None:
                if _moving:
                    return
                apps = {id(page.app): page.app for page in _open_pages}
                for page in list(_open_pages):
                    if page.controller.navigationController is not None:
                        page.stacked = True
                    elif page.stacked:
                        _open_pages.remove(page)
                        if page.on_back:
                            page.on_back()
                for app in apps.values():
                    _split(app).fit_list()

        _NAV_WATCHER = OpenDiscoNavigationWatcher.alloc().init()
    return _NAV_WATCHER


def _phone_nav(app):
    """The navigation controller of the window: the device list, and on an iPhone the pages too."""
    return app.main_window._impl.container.controller


class Page:
    """A page over the device list, holding Toga content, with the title bar's back button (and
    the swipe from the left edge) to return: then on_back runs. On an iPad beside the list, the
    device page (app.page) fills the right-hand column and the others are pushed over it."""

    def __init__(self, app, content, on_back=None):
        from toga_iOS.container import ControlledContainer
        self.app, self.content, self.laid_out, self.on_back = app, content, None, on_back
        self.stacked = False  # seen on a navigation stack
        self.container = ControlledContainer(on_refresh=lambda container: None, on_native_layout=self._layout)
        content.app = app
        self.container.content = content._impl
        self.controller = self.container.controller
        self.controller.view.backgroundColor = _class_value(_objc("UIColor"), "systemBackgroundColor")

    def _layout(self, container):
        """Lay the content out below the title bar whenever the page changes size (rotation),
        beside the list's column, which the right-hand one runs under, and above the home bar
        (the device page's tabs keep clear of it themselves)."""
        bar = (self.controller.navigationController or _phone_nav(self.app)).navigationBar
        top = bar.frame.origin.y + bar.frame.size.height
        insets = container.native.safeAreaInsets
        left = right = 0
        if _split(self.app).view is not None:
            left, right = insets.left, insets.right
        bottom = 0 if self is getattr(self.app, "page", None) else insets.bottom
        size = (container.native.bounds.size.width, container.native.bounds.size.height, top, left, right, bottom)
        if size != self.laid_out:
            self.laid_out = size
            container.top_inset, container.left_inset, container.right_inset = top, left, right
            container.bottom_inset = bottom
            self.content.refresh()

    def show(self, title: str, subtitle: str):
        from rubicon.objc import SEL
        item = self.controller.navigationItem
        if item.respondsToSelector(SEL("setSubtitle:")):  # iOS 26 and later
            item.title, item.subtitle = title, subtitle
        else:
            item.title = f"{title}  {subtitle}" if subtitle and subtitle != title else title
        if self not in _open_pages:
            _open_pages.append(self)
        split = _split(self.app)
        if split.view is not None and self is getattr(self.app, "page", None):
            if split.detail.viewControllers[0] != self.controller:  # in place of the one beside the list
                split.detail.setViewControllers([self.controller], animated=False)
        else:
            nav = split.detail if split.view is not None else _phone_nav(self.app)
            nav.delegate = _nav_watcher()
            if nav.topViewController != self.controller:
                nav.pushViewController(self.controller, animated=True)
        split.fit_list()

    def close(self):
        if self in _open_pages:
            _open_pages.remove(self)
        nav = self.controller.navigationController
        if nav is None:
            return
        stack = list(nav.viewControllers)
        index = stack.index(self.controller)
        split = _split(self.app)
        if index == 0:  # the device page beside the list: none any more
            nav.setViewControllers([split.empty], animated=False)
            clear_selection(self.app)
        else:  # this page, and any pushed over it
            nav.popToViewController(stack[index - 1], animated=True)
        split.fit_list()


class _Split:
    """The iPad's two columns: the window's own navigation controller (the device list) at the
    left, and at the right `detail`, a navigation controller holding the device page (or a note
    that none is open) with the other pages pushed over it. While one of those is open the list
    waits, dimmed, as on an iPhone, where it's under the page."""
    WIDTH = (390, 0.36, 440)  # the list's column: at least (Quick Scan, Full Scan and Stop fit), share, at most

    def __init__(self, app):
        self.app, self.view, self.detail, self.empty = app, None, None, None

    def _build(self):
        UIColor = _objc("UIColor")
        self.empty = _objc("UIViewController").alloc().init()
        self.empty.view.backgroundColor = _class_value(UIColor, "systemBackgroundColor")
        try:  # iOS 17 and later
            note = _objc("UIContentUnavailableConfiguration").emptyConfiguration()
            note.image = _objc("UIImage").systemImageNamed("network")
            note.text = _("No Device Selected")
            note.secondaryText = _("Run a Quick Scan or a Full Scan, then pick a device from the list.")
            self.empty.contentUnavailableConfiguration = note
        except Exception:
            pass
        self.detail = _objc("UINavigationController").alloc().initWithRootViewController(self.empty)
        self.detail.delegate = _nav_watcher()
        split = _objc("UISplitViewController").alloc().initWithStyle(1)  # double column
        split.preferredSplitBehavior = 1  # tile: side by side, never one over the other
        split.preferredDisplayMode = 2  # one beside the secondary
        split.presentsWithGesture = False
        split.displayModeButtonVisibility = 1  # never: no button that hides the list
        split.primaryBackgroundStyle = 0  # none: a sidebar's glass let the wallpaper through in dark mode
        split.minimumPrimaryColumnWidth, split.maximumPrimaryColumnWidth = self.WIDTH[0], self.WIDTH[2]
        split.preferredPrimaryColumnWidthFraction = self.WIDTH[1]
        self.stand_in = _objc("UIViewController").alloc().init()  # the left column while the list isn't in it
        split.setViewController(self.stand_in, forColumn=0)
        split.setViewController(self.detail, forColumn=2)
        self.split = split

    def arrange(self):
        """Side by side at a regular width, the iPhone's layout at a compact one (iPad only). Not
        while a page is up over everything (present): asked again once it's gone."""
        if not _pad() or getattr(self.app, "_presented", None) is not None:
            return
        size_class = self.app.main_window._impl.native.traitCollection.horizontalSizeClass
        if not size_class:  # not known before the window is on screen: asked again then
            return
        wide = size_class == 2  # regular
        try:
            if wide and self.view is None:
                self._expand()
            elif not wide and self.view is not None:
                self._collapse()
        except Exception:  # the layout stays as it was rather than the app stopping
            import traceback
            self.app._append_log(tr("Couldn't change the iPad layout:\n{error}", error=traceback.format_exc()),
                                 status=False)

    def _expand(self):
        global _moving
        if self.detail is None:
            self._build()
        nav = _phone_nav(self.app)
        stack = list(nav.viewControllers)
        pages = stack[1:]
        page = getattr(self.app, "page", None)
        if not pages or page is None or pages[0] != page.controller:
            pages.insert(0, self.empty)
        _moving = True
        try:
            nav.setViewControllers(stack[:1], animated=False)
            self.detail.setViewControllers(pages, animated=False)
            # The window lets go of the list's controller first: UIKit won't put a window's
            # root controller in a column.
            self.app.main_window._impl.native.rootViewController = self.split
            self.split.setViewController(nav, forColumn=0)
            self.view = self.split
        finally:
            _moving = False
        self.fit_list()

    def _collapse(self):
        global _moving
        nav = _phone_nav(self.app)
        pages = [vc for vc in self.detail.viewControllers if vc != self.empty]
        _moving = True
        try:
            self.detail.setViewControllers([self.empty], animated=False)
            self.split.setViewController(self.stand_in, forColumn=0)
            self.app.main_window._impl.native.rootViewController = nav
            nav.setViewControllers([nav.viewControllers[0], *pages], animated=False)
            self.view = None
        finally:
            _moving = False
        self.fit_list()

    def fit_list(self):
        """The list waits, dimmed, while a page is open over the device page beside it; the line
        at its edge shows while there's a page beside it."""
        waiting = self.view is not None and len(list(self.detail.viewControllers)) > 1
        view = _phone_nav(self.app).view
        view.userInteractionEnabled = not waiting
        view.alpha = 0.45 if waiting else 1.0
        if getattr(self.app, "_ios_edge", None) is not None:
            self.app._ios_edge.hidden = self.view is None


def _pad() -> bool:
    return _objc("UIDevice").currentDevice.userInterfaceIdiom == 1  # UIUserInterfaceIdiomPad


def _split(app) -> _Split:
    if not hasattr(app, "_ios_split"):
        app._ios_split = _Split(app)
    return app._ios_split


def side_by_side(app) -> bool:
    """True while the device list stays in view beside the pages (an iPad at a regular width)."""
    return _split(app).view is not None


def clear_selection(app):
    """No row marked as the device beside the list (the scan's Notes and Log are there, or nothing)."""
    native = app.table._impl.native
    path = native.indexPathForSelectedRow
    if path is not None:
        native.deselectRowAtIndexPath(path, animated=True)


def fit(app, export, notes, settings):
    """The title bar's buttons (Export at the left; Notes and Log, Settings at the right), lines
    between devices, an icon for each tab."""
    from rubicon.objc import Block, objc_id
    app._ios_blocks = []  # the buttons' handlers, kept alive

    def item(symbol, title, action):
        def tapped(_action) -> None:
            try:
                action()
            except Exception as e:  # UIKit would drop it silently
                app.status.text = f"{title}: {type(e).__name__}: {e}"

        block = Block(tapped, None, objc_id)
        app._ios_blocks.append(block)
        act = _objc("UIAction").actionWithTitle(title, image=_objc("UIImage").systemImageNamed(symbol),
                                                identifier=None, handler=block)
        return _objc("UIBarButtonItem").alloc().initWithPrimaryAction(act)

    bar = app.main_window._impl.container.content_controller.navigationItem
    export_item = item("square.and.arrow.up", _("Export"), export)
    bar.leftBarButtonItem = export_item
    bar.rightBarButtonItems = _objc("NSArray").arrayWithArray([
        item("gearshape", _("Settings"), settings), item("list.bullet.rectangle", _("Notes and Log"), notes)])
    bar.backButtonTitle = _("Devices")
    app.export_button = BarItem(export_item)
    app.export_button.enabled = False
    try:
        app.table._impl.native.separatorStyle = 1  # UITableViewCellSeparatorStyleSingleLine
        UIImage = _objc("UIImage")
        symbols = {_(title): symbol for title, symbol in TAB_SYMBOLS.items()}  # by the titles as shown
        for tab in app.tabs._impl.sub_containers:
            image = UIImage.systemImageNamed(symbols.get(str(tab.controller.tabBarItem.title), ""))
            if image:
                tab.controller.tabBarItem.image = image
        for label in app.status.widgets:  # the list's status line and Tools'
            _shortened(label)
    except Exception:
        pass  # cosmetic
    if _pad():
        _fit_pad(app)


def _fit_pad(app):
    """iPad: the list beside the pages at a regular width (_Split), following the window's width
    from then on; the device page's tabs along the bottom as on an iPhone (iPadOS puts them at the
    top, over the page, with Notes and Log behind an arrow); the list's column in the page's
    background colour, with a line between them."""
    from rubicon.objc import Block, objc_id
    try:
        app.tabs._impl.native_controller.traitOverrides.horizontalSizeClass = 1  # compact
        UIColor, view = _objc("UIColor"), _phone_nav(app).view
        view.backgroundColor = _class_value(UIColor, "systemBackgroundColor")
        # A hairline down the list's right-hand edge, where the page beside it begins.
        from rubicon.objc import CGRect
        width = 1 / _class_value(_objc("UIScreen"), "mainScreen").scale
        size = view.bounds.size
        line = _objc("UIView").alloc().initWithFrame(CGRect((size.width - width, 0), (width, size.height)))
        line.backgroundColor = _class_value(UIColor, "separatorColor")
        line.autoresizingMask = 1 | 16  # flexible left margin and height: it stays at the edge
        line.hidden = True
        view.addSubview(line)
        app._ios_edge = line
    except Exception:
        pass  # cosmetic
    split = _split(app)
    split.arrange()

    def changed(environment, previous) -> None:
        app.loop.call_soon(split.arrange)  # after UIKit's own changes for the new width

    try:  # iOS 17 and later; fit_safe_area arranges after every resize too
        app._ios_trait_block = Block(changed, None, objc_id, objc_id)
        app._ios_trait_watch = app.main_window._impl.native.registerForTraitChanges(
            _objc("NSArray").arrayWithObject(_objc("UITraitHorizontalSizeClass")), withHandler=app._ios_trait_block)
    except Exception:
        pass


def text_box(widget):
    """A text view for typing many lines into (a note, a list of subnets), shown as a gray
    rounded box: by itself it has no edge to show where it is."""
    try:
        from rubicon.objc.types import UIEdgeInsetsMake
        native = widget._impl.native
        native.backgroundColor = _class_value(_objc("UIColor"), "secondarySystemBackgroundColor")
        native.layer.cornerRadius = 10
        native.textContainerInset = UIEdgeInsetsMake(8, 6, 8, 6)
    except Exception:
        pass  # cosmetic


def search_field(app, widget):
    """The search above the list drawn as iOS draws its own: a magnifying glass in a gray
    rounded field, a button that clears it, and Search on the keyboard."""
    try:
        from rubicon.objc import CGRect, NSInteger, send_message
        UIColor, native = _objc("UIColor"), widget._impl.native
        native.borderStyle = 0  # none: the fill shows the field
        native.backgroundColor = _class_value(UIColor, "tertiarySystemFillColor")
        native.layer.cornerRadius = 10
        glass = _objc("UIImageView").alloc().initWithImage(_objc("UIImage").systemImageNamed("magnifyingglass"))
        glass.tintColor = _class_value(UIColor, "secondaryLabelColor")
        glass.contentMode = 4  # centred
        glass.frame = CGRect((8, 0), (20, 20))
        room = _objc("UIView").alloc().initWithFrame(CGRect((0, 0), (32, 20)))  # keeps the text off it
        room.addSubview(glass)
        native.leftView = room
        native.leftViewMode = 3  # always
        widget.style.update(height=36)  # a search bar's height: without its border the field shrank
        native.clearButtonMode = 1  # while typing
        plain_entry(widget)
        send_message(native, "setReturnKeyType:", 6, restype=None, argtypes=[NSInteger])  # Search
    except Exception:
        pass  # cosmetic


def export_menu(app, choices, pick):
    """Export opens a menu of the reports, listed afresh each time it opens: the Site Report, the
    scan's data, then the security report, config backups, notes and the Log, each saying what's
    in it (and dimmed while there's nothing). Choosing one saves it and offers it to the share
    sheet (the Site Report asks for the site's name first)."""
    def items():
        return [(title, enabled, lambda kind=kind: pick(kind), detail, EXPORT_SYMBOLS.get(kind, "doc"))
                for kind, title, detail, enabled in choices()]

    try:
        item = app.export_button.native
        item.menu = _deferred_menu(app, app, items)
        item.primaryAction = None  # a tap opens the menu
        app.export_button.menu = True
        app.export_button.enabled = True
    except Exception:
        pass  # Export saves the Site Report, as before


def _deferred_menu(app, owner, items):
    """A UIMenu listed afresh each time it opens, from items(): (title, enabled, action), or
    with a line under the title and an SF Symbol: (title, enabled, action, detail, symbol)."""
    from rubicon.objc import Block, objc_id
    from rubicon.objc.api import ObjCBlock
    UIAction, UIImage = _objc("UIAction"), _objc("UIImage")

    def provide(completion) -> None:
        owner._ios_menu_blocks = []  # the open menu's handlers, kept alive while it's up
        actions = []
        for title, enabled, action, *more in items():
            detail, symbol = (more + ["", ""])[:2]
            block = Block(lambda _action, action=action: action(), None, objc_id)
            owner._ios_menu_blocks.append(block)
            element = UIAction.actionWithTitle(title, image=UIImage.systemImageNamed(symbol) if symbol else None,
                                               identifier=None, handler=block)
            if detail:
                try:
                    element.subtitle = detail  # iOS 15 and later
                except Exception:
                    pass
            if not enabled:
                element.attributes = 1  # UIMenuElementAttributesDisabled
            actions.append(element)
        ObjCBlock(completion, None, objc_id)(_objc("NSArray").arrayWithArray(actions))

    owner._ios_menu_provider = Block(provide, None, objc_id)
    deferred = _objc("UIDeferredMenuElement").elementWithUncachedProvider(owner._ios_menu_provider)
    return _objc("UIMenu").menuWithTitle("", children=_objc("NSArray").arrayWithObject(deferred))


def menu_button(app, title: str, items):
    """A gray button that opens a menu of items() (Copy: the IP or the MAC address)."""
    try:
        button = toga.Button(title, style=Pack(flex=1))
        native = button._impl.native
        native.menu = _deferred_menu(app, button, items)
        native.showsMenuAsPrimaryAction = True
        style_button(button, "gray")
        return button
    except Exception:
        return None  # phone.py lays out a button for each


def bar_button(app, symbol: str, title: str, action):
    """One more button in the title bar, at the right, left of Notes and Log."""
    try:
        from rubicon.objc import Block, objc_id

        def tapped(_action) -> None:
            try:
                action()
            except Exception as e:  # UIKit would drop it silently
                app.status.text = f"{title}: {type(e).__name__}: {e}"

        block = Block(tapped, None, objc_id)
        app._ios_blocks.append(block)
        act = _objc("UIAction").actionWithTitle(title, image=_objc("UIImage").systemImageNamed(symbol),
                                                identifier=None, handler=block)
        item = _objc("UIBarButtonItem").alloc().initWithPrimaryAction(act)
        bar = app.main_window._impl.container.content_controller.navigationItem
        bar.rightBarButtonItems = _objc("NSArray").arrayWithArray([*bar.rightBarButtonItems, item])
    except Exception:
        pass


_PICKER_DELEGATE = None


async def open_file(app):
    """A file picked in Files (a copy in the app's own folder), as a path; None when cancelled."""
    global _PICKER_DELEGATE
    from rubicon.objc import NSObject, objc_method
    if _PICKER_DELEGATE is None:
        class OpenDiscoPickerDelegate(NSObject):
            @objc_method
            def documentPicker_didPickDocumentsAtURLs_(self, picker, urls) -> None:
                paths = [str(url.path) for url in urls]
                self.done(paths[0] if paths else None)

            @objc_method
            def documentPickerWasCancelled_(self, picker) -> None:
                self.done(None)

        _PICKER_DELEGATE = OpenDiscoPickerDelegate
    answer = app.loop.create_future()
    delegate = _PICKER_DELEGATE.alloc().init()
    delegate.done = lambda path: answer.done() or answer.set_result(path)
    kinds = _objc("NSArray").arrayWithObject(_objc("UTType").typeWithIdentifier("public.data"))
    picker = _objc("UIDocumentPickerViewController").alloc().initForOpeningContentTypes(kinds, asCopy=True)
    picker.delegate = delegate
    app._ios_picker = (picker, delegate)  # kept alive while it's up
    shown = app.main_window._impl.native.rootViewController
    while shown.presentedViewController:
        shown = shown.presentedViewController
    shown.presentViewController(picker, animated=True, completion=None)
    try:
        return await answer
    finally:
        app._ios_picker = None


def here(app) -> str:
    """What the app's text calls the device it runs on."""
    return _("this iPad") if _pad() else _("this iPhone")


def _shortened(label):
    """A one-line label that ends in … where its text doesn't fit: Toga makes a label at least
    as wide as its text, which pushed the end of a long status past the screen's edge."""
    from travertino.size import at_least
    impl = label._impl
    rehint = impl.rehint

    def shortening():
        rehint()
        label.intrinsic.width = at_least(0)

    impl.rehint = shortening
    impl.native.lineBreakMode = 4  # NSLineBreakByTruncatingTail
    label.refresh()


def wrap_switch(switch):
    """A switch's text in as many lines as it takes: iOS gives it one, and a long one (a
    translation, say) pushed the switch past the screen's edge. (Toga's Switch keeps a text's
    first line only, so the lines go to the label itself.)"""
    from rubicon.objc import CGSize, send_message
    try:
        label = switch._impl.native_label
        text = str(label.text)
        room = float(_class_value(_objc("UIScreen"), "mainScreen").bounds.size.width) - 110  # (the switch, margins)
        wide = send_message(label, "intrinsicContentSize", restype=CGSize, argtypes=[]).width
        if wide <= room or "\n" in text:
            return
        label.numberOfLines = 0
        switch._impl.set_text(i18n.fill(text, max(10, int(i18n.width(text) * room / wide))))
        impl, rehint = switch._impl, switch._impl.rehint

        def whole_lines():  # (Toga's layout drops a fraction of a point: the second line went to "…")
            rehint()
            switch.intrinsic.height = math.ceil(switch.intrinsic.height)

        impl.rehint = whole_lines
        switch.refresh()
    except Exception:
        pass  # cosmetic


def style_button(button, kind="filled", color=None):
    """A rounded, filled or tinted iOS button (UIButton.Configuration) in place of plain text."""
    try:
        Config = _objc("UIButtonConfiguration")
        config = {"filled": Config.filledButtonConfiguration, "tinted": Config.tintedButtonConfiguration,
                  "gray": Config.grayButtonConfiguration}[kind]()
        config.cornerStyle = 4  # capsule
        config.titleLineBreakMode = 4  # one line, ending in … if it must: never "Can-cel" over two
        styled = button._impl.native.configuration  # styled before: Toga's own title is gone
        config.title = button.text if styled is None else str(styled.title)
        if color:
            tint = _class_value(_objc("UIColor"), color)
            config.baseForegroundColor = tint
            config.baseBackgroundColor = tint
        native = button._impl.native
        native.setTitle(None, forState=0)  # Toga's title would keep its own colour: blue on the blue fill
        native.configuration = config
        _natural_size(button)
        button.refresh()
    except Exception:
        pass  # cosmetic: a plain button still works


def _natural_size(button):
    """Size a styled button by its whole title in the capsule: Toga takes the smallest it can be
    squeezed to, which cut a title short ("Can…") where nothing made the button wider."""
    from math import ceil
    from rubicon.objc import CGSize, send_message
    from travertino.size import at_least
    impl = button._impl

    def rehint():
        size = send_message(impl.native, "intrinsicContentSize", restype=CGSize, argtypes=[])
        button.intrinsic.width = at_least(ceil(size.width))
        button.intrinsic.height = ceil(size.height)

    impl.rehint = rehint
    rehint()


def retitle(button, text: str):
    """Change a button's text, styled or not."""
    native = button._impl.native
    config = native.configuration
    if config is None:
        button.text = text
    elif str(config.title) != text:
        config.title = text
        native.configuration = config
        button.refresh()


def fix_text_scrolling():
    """Toga pins a many-line text box's placeholder to the box's edges, which in a scroll view
    are its content's: Auto Layout then sized the content to the empty placeholder (4×8 points),
    so a finger couldn't scroll the text (the terms of use, the licenses, Details) until the app
    had scrolled it itself. Pinned to the box's frame instead, where it shows, and nothing else."""
    try:
        from toga_iOS.widgets.multilinetextinput import MultilineTextInput
    except ImportError:
        return

    def constrain_placeholder_label(self):
        label, frame = self.placeholder_label, self.native.frameLayoutGuide
        _objc("NSLayoutConstraint").activateConstraints([
            label.leadingAnchor.constraintEqualToAnchor(frame.leadingAnchor, constant=4.0),
            label.trailingAnchor.constraintEqualToAnchor(frame.trailingAnchor),
            label.topAnchor.constraintEqualToAnchor(frame.topAnchor, constant=8.0)])

    MultilineTextInput.constrain_placeholder_label = constrain_placeholder_label


def monospaced(text, size: float):
    """The system's monospaced font (SF Mono), which reads better than the Courier Toga picks."""
    try:
        font = _objc("UIFont").monospacedSystemFontOfSize(size, weight=0.0)
        text._impl.native.font = font
        placeholder = getattr(text._impl, "placeholder_label", None)  # Toga's own label over the text
        if placeholder is not None:
            placeholder.font = font
    except Exception:
        pass  # cosmetic


def copy_text(text: str):
    _class_value(_objc("UIPasteboard"), "generalPasteboard").string = text


def keep_selection(app, key):
    """The list forgets which row was tapped whenever a row changes, and with it which device
    Tools works on: select the same device again."""
    if key is None:
        return
    index = next((i for i, row in enumerate(app.table.data) if getattr(row, "key", None) == key), None)
    if index is None:
        return
    try:
        path = _objc("NSIndexPath").indexPathForRow(index, inSection=0)
        app.table._impl.native.selectRowAtIndexPath(path, animated=False, scrollPosition=0)  # no scrolling
    except Exception:
        pass


def fit_safe_area(app):
    """Keep the device list inside the screen's rounded corners and clear of the home bar (and,
    turned sideways, the camera cutout): Toga lays it out to the very edges. On an iPad, the
    list beside the pages or not, for the window's new width."""
    if _pad():
        _split(app).arrange()
    try:
        inset = app.main_window._impl.native.safeAreaInsets
        style = app.main_content.style
        style.margin_bottom = max(10, int(inset.bottom))
        style.margin_left, style.margin_right = max(10, int(inset.left)), max(10, int(inset.right))
    except Exception:
        pass  # cosmetic


READABLE_WIDTH = 640  # a page over everything gets no wider (an iPad, a phone turned sideways)


def present(app, content):
    """A page over everything, which can't be swiped away (the terms of use, until they're agreed
    to), laid out inside the safe area, in the middle and at most READABLE_WIDTH wide. An iPad's
    layout waits while it's up (_Split.arrange): a new root controller for the window would take
    it away, leaving the app usable without it. Returns what takes it away."""
    from rubicon.objc import Block
    from toga_iOS.container import ControlledContainer
    laid_out = []

    def layout(container):
        insets = container.native.safeAreaInsets
        size = (container.native.bounds.size.width, container.native.bounds.size.height,
                insets.top, insets.left, insets.right, insets.bottom)
        if [size] != laid_out:
            laid_out[:] = [size]
            spare = max(0.0, (size[0] - insets.left - insets.right - READABLE_WIDTH) / 2)
            container.top_inset, container.left_inset = insets.top, insets.left + spare
            container.right_inset, container.bottom_inset = insets.right + spare, insets.bottom
            content.refresh()

    container = ControlledContainer(on_refresh=lambda container: None, on_native_layout=layout)
    content.app = app
    container.content = content._impl
    controller = container.controller
    controller.view.backgroundColor = _class_value(_objc("UIColor"), "systemBackgroundColor")
    controller.modalPresentationStyle = 0  # full screen
    controller.setModalInPresentation(True)  # no swiping it away (as a property, rubicon kept it to itself)
    shown = app.main_window._impl.native.rootViewController
    while shown.presentedViewController:
        shown = shown.presentedViewController
    shown.presentViewController(controller, animated=False, completion=None)
    app._presented = container  # kept alive while it's up

    def dismissed() -> None:
        app._presented = None
        fit_safe_area(app)  # an iPad's layout for the window's width now

    app._ios_dismissed = Block(dismissed, None)
    return lambda: controller.dismissViewControllerAnimated(True, completion=app._ios_dismissed)


def share(app, path: Path):
    """Offer a file to the share sheet: Save to Files, Mail, AirDrop, Messages…"""
    from rubicon.objc import Block, objc_id
    url = _objc("NSURL").fileURLWithPath(str(path))
    sheet = _objc("UIActivityViewController").alloc().initWithActivityItems(
        _objc("NSArray").arrayWithObject(url), applicationActivities=None)
    popover = sheet.popoverPresentationController  # iPad: the sheet points at the Export button
    if popover:
        popover.barButtonItem = app.export_button.native

    def done(activity, completed: bool, items, error) -> None:
        app.status.text = tr("Shared {name}", name=path.name) if completed else _("Export not shared.")

    app._share_done = Block(done, None, objc_id, bool, objc_id, objc_id)  # kept alive while it's up
    sheet.completionWithItemsHandler = app._share_done
    shown = app.main_window._impl.native.rootViewController
    while shown.presentedViewController:
        shown = shown.presentedViewController
    shown.presentViewController(sheet, animated=True, completion=None)
    app.status.text = tr("Saved {name}: share it to Files, Mail or AirDrop.", name=path.name)


class Picker:
    """A pop-up button: it shows the item chosen, and tapping it lists the others (iOS 15's
    pop-up menu, in place of Toga's picker wheel)."""

    def __init__(self, app, items):
        from rubicon.objc import Block, objc_id
        self.items, self.value = list(items), items[0]
        self.widget = toga.Button(items[0], style=Pack(flex=1))
        self._blocks = []
        actions = []
        for item in self.items:
            def picked(_action, item=item) -> None:
                self.value = item

            self._blocks.append(Block(picked, None, objc_id))
            actions.append(_objc("UIAction").actionWithTitle(item, image=None, identifier=None,
                                                             handler=self._blocks[-1]))
        actions[0].state = 1  # UIMenuElementStateOn: the one chosen
        native = self.widget._impl.native
        native.menu = _objc("UIMenu").menuWithTitle("", children=_objc("NSArray").arrayWithArray(actions))
        native.showsMenuAsPrimaryAction = True
        native.changesSelectionAsPrimaryAction = True
        style_button(self.widget, "gray")


def watch_keyboard(app, widget, follow: bool = True):
    """Keep a text view clear of the on-screen keyboard while it's up: the part it covers can be
    scrolled into view. follow: show its last lines (the SSH session's console, as commands are
    typed under it); otherwise the text being edited stays where it is (the config editor)."""
    try:
        from rubicon.objc import Block, ObjCInstance, objc_id
        from rubicon.objc.types import UIEdgeInsetsMake
        center = _class_value(_objc("NSNotificationCenter"), "defaultCenter")

        def moved(note) -> None:
            view = widget._impl.native
            if view.window is None:
                return
            keyboard = ObjCInstance(note).userInfo.objectForKey("UIKeyboardFrameEndUserInfoKey").CGRectValue
            mine = view.convertRect(view.bounds, toView=None)
            covered = max(0.0, mine.origin.y + mine.size.height - keyboard.origin.y)
            view.contentInset = UIEdgeInsetsMake(0, 0, covered, 0)
            view.verticalScrollIndicatorInsets = UIEdgeInsetsMake(0, 0, covered, 0)
            if follow:
                widget.scroll_to_bottom()
            elif view.isFirstResponder() and covered:  # the line being edited comes out from under it
                view.scrollRangeToVisible(view.selectedRange)

        if not hasattr(app, "_keyboard_watchers"):
            app._keyboard_watchers = []  # (block, observer) for each view, kept alive
        block = Block(moved, None, objc_id)
        app._keyboard_watchers.append((block, center.addObserverForName(
            "UIKeyboardWillChangeFrameNotification", object=None, queue=None, usingBlock=block)))
    except Exception:
        pass  # the console still scrolls by hand


def plain_entry(widget, send: bool = False, new_password: bool = False):
    """A text field for usernames, passwords, ports and shell commands: no capital first letter,
    no corrections, no smart quotes; send: its return key reads "send". new_password: a new
    password for a device, which iOS mustn't take over with a "strong password" of its own (that
    blanks the field and swallows typing): marked as a one-time code instead. (Set through the
    setters: rubicon doesn't find UITextInputTraits' properties on a UITextField.)"""
    native = widget._impl.native
    if new_password:
        try:
            from rubicon.objc import send_message, objc_id
            from rubicon.objc.api import ns_from_py
            send_message(native, "setTextContentType:", ns_from_py("one-time-code"), restype=None,
                         argtypes=[objc_id])
            native.passwordRules = None
        except Exception:
            pass
    for setter, value in (("setAutocapitalizationType:", 0), ("setAutocorrectionType:", 1),
                          ("setSpellCheckingType:", 1), ("setSmartQuotesType:", 1), ("setSmartDashesType:", 1),
                          ("setSmartInsertDeleteType:", 1), *((("setReturnKeyType:", 7),) if send else ())):
        try:
            from rubicon.objc import NSInteger, send_message
            send_message(native, setter, value, restype=None, argtypes=[NSInteger])
        except Exception:
            pass


def end_editing(app):
    """Finish typing: the text field gives up the keyboard, and its last character (still
    pending in a password field) is in its value."""
    try:
        app.main_window._impl.native.endEditing(True)
    except Exception:
        pass


def done_bar(app, widget):
    """A Done button above the keyboard for a text view that takes many lines (the config
    editor), where Return is a new line: Done puts the keyboard away. Dragging the text down
    does too."""
    try:
        from rubicon.objc import Block, objc_id
        if not hasattr(app, "_done_blocks"):
            app._done_blocks = []  # kept alive
        block = Block(lambda action: end_editing(app), None, objc_id)
        app._done_blocks.append(block)
        UIBarButtonItem = _objc("UIBarButtonItem")
        done = _objc("UIAction").actionWithTitle(_("Done"), image=None, identifier=None, handler=block)
        bar = _objc("UIToolbar").alloc().init()
        bar.items = _objc("NSArray").arrayWithArray([UIBarButtonItem.flexibleSpaceItem(),
                                                     UIBarButtonItem.alloc().initWithPrimaryAction(done)])
        bar.sizeToFit()
        native = widget._impl.native
        native.inputAccessoryView = bar
        native.keyboardDismissMode = 2  # UIScrollViewKeyboardDismissModeInteractive
    except Exception:
        pass
