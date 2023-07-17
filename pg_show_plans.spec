%global sname pg_show_plans

%ifarch ppc64 ppc64le s390 s390x armv7hl
 %if 0%{?rhel} && 0%{?rhel} == 7
  %{!?llvm:%global llvm 0}
 %else
  %{!?llvm:%global llvm 1}
 %endif
%else
 %{!?llvm:%global llvm 1}
%endif

Summary:	A PostgreSQL extension that shows query plans of all the currently running SQL statements.
Name:		%{sname}_%{pgmajorversion}
Version:	1.1.4
Release:	2%{?dist}.1
License:	PostgreSQL
Source0:	https://github.com/cybertec-postgresql/%{sname}/archive/%{version}/%{sname}-%{version}.tar.gz
URL:		https://github.com/cybertec-postgresql/%{sname}
BuildRequires:	postgresql%{pgmajorversion}-devel pgdg-srpm-macros
Requires:	postgresql%{pgmajorversion}-server

%description
%{sname} is a PostgreSQL extension that shows query plans of all the currently
running SQL statements. Query plans can be shown in several formats, like JSON.

%if %llvm
%package llvmjit
Summary:	Just-in-time compilation support for %{sname}
Requires:	%{name}%{?_isa} = %{version}-%{release}
%if 0%{?rhel} && 0%{?rhel} == 7
%ifarch aarch64
Requires:	llvm-toolset-7.0-llvm >= 7.0.1
%else
Requires:	llvm5.0 >= 5.0
%endif
%endif
%if 0%{?suse_version} >= 1315 && 0%{?suse_version} <= 1499
BuildRequires:  llvm6-devel clang6-devel
Requires:	llvm6
%endif
%if 0%{?suse_version} >= 1500
BuildRequires:  llvm15-devel clang15-devel
Requires:	llvm15
%endif
%if 0%{?fedora} || 0%{?rhel} >= 8
Requires:	llvm => 5.0
%endif

%description llvmjit
This packages provides JIT support for %{sname}
%endif

%prep
%setup -q -n %{sname}-%{version}

%build
PATH=%{pginstdir}/bin/:$PATH %{__make} %{?_smp_mflags}

%install
%{__rm} -rf %{buildroot}
PATH=%{pginstdir}/bin/:$PATH %{__make} %{?_smp_mflags} install DESTDIR=%{buildroot}

%clean
%{__rm} -rf %{buildroot}

%files
%license LICENSE
%defattr(644,root,root,755)
%{pginstdir}/share/extension/%{sname}*.sql
%{pginstdir}/share/extension/%{sname}.control
%{pginstdir}/lib/%{sname}.so
%doc %{pginstdir}/doc/extension/%{sname}.md

%if %llvm
%files llvmjit
   %{pginstdir}/lib/bitcode/%{sname}*.bc
   %{pginstdir}/lib/bitcode/%{sname}/*.bc
%endif

%changelog
* Mon Nov 5 2018 Ivan Kovmir <ivan.kovmir@cybertec.at> - 1.1.4-1
- Initial RPM packaging
