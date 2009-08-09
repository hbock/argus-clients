%define name    argus-clients
%define ver     3.0
%define rel     0
Summary: Argus Client Software
Name: argus-clients
Version: %ver
Release: %rel
License: see /usr/local/argus/COPYING
Group: Applications/Internet
Source0: ftp://ftp.qosient.com/argus/%{name}-%{ver}.%{rel}.tar.gz
URL: http://qosient.com/argus

%description
Argus Clients contains a number of programs that process Argus data.
Copyright: 2000-2008 QoSient, LLC

%define argusdir        /usr/local
%define argusbin        %{argusdir}/bin
%define argusdata       %{argusdir}/argus
%define arguslib        %{argusdata}/lib
%define argusdocs       /usr/share/doc/%{name}-%{ver}

%prep
%setup -n %{name}-%{ver}.%{rel}
%build
%configure --prefix=/usr
make
mkdir -p %{argusdir}
mkdir -p %{argusbin}
mkdir -p %{argusdocs}
mkdir -p %{argusdata}
mkdir -p %{arguslib}

cp -Rp support %{argusdocs}
cp -Rp doc/* %{argusdocs}

install -m 0555 -o root -g root bin/ra           %{argusbin}
install -m 0555 -o root -g root bin/rabins       %{argusbin}
install -m 0555 -o root -g root bin/racluster    %{argusbin}
install -m 0555 -o root -g root bin/racount      %{argusbin}
install -m 0555 -o root -g root bin/radium       %{argusbin}
install -m 0555 -o root -g root bin/ragraph      %{argusbin}
install -m 0555 -o root -g root bin/ragrep       %{argusbin}
install -m 0555 -o root -g root bin/rahisto      %{argusbin}
install -m 0555 -o root -g root bin/ramatrix     %{argusbin}
install -m 0555 -o root -g root bin/ranonymize   %{argusbin}
install -m 0555 -o root -g root bin/rapath       %{argusbin}
install -m 0555 -o root -g root bin/rapolicy     %{argusbin}
install -m 0555 -o root -g root bin/rasort       %{argusbin}
install -m 0555 -o root -g root bin/rasplit      %{argusbin}
install -m 0555 -o root -g root bin/rastrip      %{argusbin}
install -m 0555 -o root -g root bin/ratop        %{argusbin}
install -m 0555 -o root -g root bin/raxml        %{argusbin}

install -m 0444 -o root -g root man/man1/ra* %{_mandir}/man1/
install -m 0444 -o root -g root man/man5/*.5 %{_mandir}/man5/
install -m 0444 -o root -g root man/man8/*.8 %{_mandir}/man8/

install -m 0644 -o root -g root support/Config/ranonymize.conf %{argusdata}
install -m 0644 -o root -g root support/Config/racluster.conf  %{argusdata}
install -m 0644 -o root -g root support/Config/radium.conf     %{argusdata}
install -m 0644 -o root -g root support/Config/rarc            %{argusdata}/ra.conf

%post

%preun

%postun

%files
%defattr(-,root,root)
%{argusbin}/ra
%{argusbin}/rabins
%{argusbin}/racluster
%{argusbin}/racount
%{argusbin}/radium
%{argusbin}/ragrep
%{argusbin}/rasort
%{argusbin}/rasplit
%{argusbin}/rastrip
%{argusbin}/ratop

%{argusdata}/ra.conf

%doc %{argusdocs}
%{_mandir}/man1/ra.1
%{_mandir}/man1/rabins.1
%{_mandir}/man1/racluster.1
%{_mandir}/man1/racount.1
%{_mandir}/man1/rasort.1
%{_mandir}/man1/rasplit.1
%{_mandir}/man5/rarc.5
%{_mandir}/man5/racluster.5
%{_mandir}/man8/radium.8
