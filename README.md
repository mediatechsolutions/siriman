# Simple Risk Management

The idea behind SIRIMAN is to build a tool that allows you to build reports in three steps:

1. Discover actives. Taking a "sources" file, it is able to discover what is behind it.
2. Modify the actives manually. Some information is not available (or should not) and other has to be modified by hand, like the impact or probability for each threat.
3. Generate the report. So we could filter what should include or the format.

The advantage of using yaml as middle language is that it is easy to be modified by humans, easy to understand and can be uploaded to a repository to maintain history.

## Usage

As said before, just three steps:

### Discover actives

In an empty directory, let's say `assessments`, create a file called `sources.yaml` with this content:

```
- name: localhost
  type: url
  addresses:
    - address: localhost
      ports:
      - 22
      - 80
      - 443
```

This fails tells to SIRIMAN to discover any active in localhost, but only centers on ports 22, 80 and 443. `ports` entry can be removed in order to scan them all.

With this active it is possible to run SIRIMAN:

```
python siriman.py discover --directory assessments
```

And a number of new yamls will be generated in `assessments` directory.

### Modify the actives

It is possible to modify those actives manually in order to decide which information to show or change the impact or probability for any threat.

Now it is using Magerit v3 and just Spanish is supported, but this may change in a near future.

### Generate the report

Just run :

```
python siriman.py report --directory assessments --output report
```

And the HTML report will be generated. Currently just HTML is supported.

### All this in just one command

It is possible to discover and generate the report in just one step. It is useful to see the initial state by using default data:

```
python siriman.py discover report --directory assessments --output report
```

The input is just the file `assessments/sources.yaml`

# Disclaimer and license

You can distribute SIRIMAN under CC-BY 2.0 (Creative Commons with Attribution).

Anyway, remember it is in its first stages and it may have a number of bugs, but it is a proof of concept in order to see what needs to be improved.

